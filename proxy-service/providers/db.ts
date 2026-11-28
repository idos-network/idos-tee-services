import {
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { kmsDecrypt, kmsGenerateDataKey } from "@idos/nitro-nsm/kms-decrypt.ts";
import { decryptGcm, encryptGcm } from "@idos/tee-common/aes-gcm.ts";
import { traced } from "@idos/tee-common/telemetry.ts";
import { AWS_KMS_ARMED_ARN, DYNAMODB_ARMED_TABLE } from "../env.ts";
import type { ArmRequest } from "../utils/dto.ts";

// Fail at boot, not on the first request.
if (!DYNAMODB_ARMED_TABLE) throw new Error("DYNAMODB_ARMED_TABLE is not set");
if (!AWS_KMS_ARMED_ARN) throw new Error("AWS_KMS_ARMED_ARN is not set");

// Region and credentials from the SDK defaults (AWS_REGION, instance role via IMDS). The SDK
// sets no timeouts: without them a stalled vsock connection hangs the request and is never retried.
// accountIdEndpointMode off: only dynamodb.<region>.amazonaws.com is mapped through vsock, never
// the <account>.ddb.<region> endpoint the SDK would pick if the credentials carried an account ID.
const client = new DynamoDBClient({
  accountIdEndpointMode: "disabled",
  // throwOnRequestTimeout: without it a request timeout only logs a warning and keeps waiting.
  requestHandler: { connectionTimeout: 1_000, requestTimeout: 3_000, throwOnRequestTimeout: true },
});

// Every record has its own AES-256 data key from KMS (AWS_KMS_ARMED_ARN), generated and unwrapped
// with this enclave's attestation, so no long-lived key exists to leak: one leaked data key opens
// one record, and every unwrap is a kms:Decrypt in CloudTrail with the armedId in its context.
// An unwrapped key stays in memory for DATA_KEY_TTL_MS after its unwrap, then is evicted.
const DATA_KEY_TTL_MS = 10 * 60 * 1000;
// One entry per armedId, valid only for the wrapped key it was unwrapped from: a key cached for
// one record never decrypts another, so KMS checks every record's own context.
// shortcut: unbounded; fine for the few hundred armed records we hold, add an LRU bound if that grows.
type CachedKey = { wrapped: string; key: Promise<Buffer>; timer: NodeJS.Timeout };
const dataKeys = new Map<string, CachedKey>();

function evictDataKey(armedId: string, entry = dataKeys.get(armedId)) {
  if (entry && dataKeys.get(armedId) === entry) {
    clearTimeout(entry.timer);
    dataKeys.delete(armedId);
  }
}

function unwrapDataKey(armedId: string, wrappedKey: Uint8Array): Promise<Buffer> {
  const wrapped = Buffer.from(wrappedKey).toString("base64");
  const cached = dataKeys.get(armedId);
  if (cached?.wrapped === wrapped) {
    return cached.key;
  }
  evictDataKey(armedId);

  // KeyId pinned: KMS refuses a wrapped key from any other key this role can decrypt with.
  // Concurrent requests share one KMS call; a failed one isn't cached.
  const key = kmsDecrypt(wrappedKey, { keyId: AWS_KMS_ARMED_ARN, encryptionContext: { armedId } });
  const entry: CachedKey = {
    wrapped,
    key,
    timer: setTimeout(() => evictDataKey(armedId, entry), DATA_KEY_TTL_MS).unref(),
  };
  dataKeys.set(armedId, entry);
  key.catch(() => evictDataKey(armedId, entry));
  return key;
}

// Item: armedId (S), dataKeyEnc (B, KMS-wrapped data key bound to the armedId), dataEnc (B),
// createdAt (N, epoch ms). Everything else is in one AES-GCM blob with the armedId as AAD, so a
// table writer can neither swap the host key / environment nor copy a blob between records.
export type Armed = ArmRequest & { id: string };

export const storeArmed = traced("db.storeArmed", async (armedId: string, data: ArmRequest) => {
  const { plaintext, ciphertext } = await kmsGenerateDataKey(AWS_KMS_ARMED_ARN, { armedId });

  await client.send(
    new PutItemCommand({
      TableName: DYNAMODB_ARMED_TABLE,
      Item: {
        armedId: { S: armedId },
        dataKeyEnc: { B: ciphertext },
        dataEnc: { B: encryptGcm(plaintext, JSON.stringify(data), armedId) },
        createdAt: { N: String(Date.now()) },
      },
      // No attribute_not_exists: ids are random UUIDs, and an SDK retry of a put that landed
      // would fail the condition and report a stored record as an error.
    }),
  );
});

export const getArmed = traced("db.getArmed", async (armedId: string): Promise<Armed | null> => {
  const { Item } = await client.send(
    new GetItemCommand({
      TableName: DYNAMODB_ARMED_TABLE,
      Key: { armedId: { S: armedId } },
      ConsistentRead: true,
    }),
  );

  if (!Item?.dataEnc?.B || !Item.dataKeyEnc?.B) {
    return null;
  }

  const key = await unwrapDataKey(armedId, Item.dataKeyEnc.B);
  const data: ArmRequest = JSON.parse(decryptGcm(key, Item.dataEnc.B, armedId).toString("utf8"));

  return { id: armedId, ...data };
});

/** Idempotent: deleting a missing record succeeds, so an SDK retry of a delete that landed does too. */
export const deleteArmed = traced("db.deleteArmed", async (armedId: string) => {
  evictDataKey(armedId);
  await client.send(
    new DeleteItemCommand({ TableName: DYNAMODB_ARMED_TABLE, Key: { armedId: { S: armedId } } }),
  );
});
