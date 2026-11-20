import {
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { createAesGcm } from "@idos/tee-common/aes-gcm.ts";
import { traced } from "@idos/tee-common/telemetry.ts";
import { DYNAMODB_ARMED_TABLE, FLE_MASTER_KEY } from "../env.ts";
import type { ArmRequest } from "../utils/dto.ts";

// Fail at boot, not on the first request, like the master key check below.
if (!DYNAMODB_ARMED_TABLE) throw new Error("DYNAMODB_ARMED_TABLE is not set");

// Region and credentials from the SDK defaults (AWS_REGION, instance role via IMDS). The SDK
// sets no timeouts: without them a stalled vsock connection hangs the request and is never retried.
// accountIdEndpointMode off: only dynamodb.<region>.amazonaws.com is mapped through vsock, never
// the <account>.ddb.<region> endpoint the SDK would pick if the credentials carried an account ID.
const client = new DynamoDBClient({
  accountIdEndpointMode: "disabled",
  // throwOnRequestTimeout: without it a request timeout only logs a warning and keeps waiting.
  requestHandler: { connectionTimeout: 1_000, requestTimeout: 3_000, throwOnRequestTimeout: true },
});

// Key derived from the master key, which scripts/run.ash decrypts with attestation.
const aead = createAesGcm(FLE_MASTER_KEY, "proxy-armed-v1");

// Item: armedId (S), dataEnc (B), createdAt (N, epoch ms). Everything (incl. the armedId) is in
// one AES-GCM blob, so a table writer can neither swap the host key / environment nor copy a
// blob between records.
export type Armed = ArmRequest & { id: string };

export const storeArmed = traced("db.storeArmed", async (armedId: string, data: ArmRequest) => {
  await client.send(
    new PutItemCommand({
      TableName: DYNAMODB_ARMED_TABLE,
      Item: {
        armedId: { S: armedId },
        dataEnc: { B: aead.encrypt(JSON.stringify({ armedId, ...data })) },
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

  if (!Item?.dataEnc?.B) {
    return null;
  }

  const { armedId: blobArmedId, ...data }: ArmRequest & { armedId: string } = JSON.parse(
    aead.decrypt(Item.dataEnc.B).toString("utf8"),
  );

  if (blobArmedId !== armedId) {
    throw new Error(`Armed record ${armedId} holds a blob for armedId ${blobArmedId}`);
  }

  return { id: armedId, ...data };
});

/** Idempotent: deleting a missing record succeeds, so an SDK retry of a delete that landed does too. */
export const deleteArmed = traced("db.deleteArmed", async (armedId: string) => {
  await client.send(
    new DeleteItemCommand({ TableName: DYNAMODB_ARMED_TABLE, Key: { armedId: { S: armedId } } }),
  );
});
