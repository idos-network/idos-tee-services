import {
  type AttributeValue,
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  ScanCommand,
} from "@aws-sdk/client-dynamodb";
import { createAesGcm } from "@idos/tee-common/aes-gcm.ts";
import { traced } from "@idos/tee-common/telemetry.ts";
import type { BoxKeyPair } from "tweetnacl";
import { DYNAMODB_SESSIONS_TABLE, FLE_MASTER_KEY, SESSION_TTL_SECONDS } from "../env.ts";

// Fail at boot, not on the first request, like the master key check below.
if (!DYNAMODB_SESSIONS_TABLE) throw new Error("DYNAMODB_SESSIONS_TABLE is not set");

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
const aead = createAesGcm(FLE_MASTER_KEY, "enclave-session-v1");

// The record's plaintext fields a table writer could otherwise swap or edit (the client key
// authenticates the session, createdAt (epoch ms) sets its expiry).
interface BoundFields {
  sessionId: string;
  sessionClientPublicKeyB64: string;
  sessionServerPublicKeyB64: string;
  createdAt: number;
}

// The AAD binds each blob to its field and to the record's plaintext fields: changing any of
// them, or moving a blob to another session or field, fails decryption.
const aad = (record: BoundFields, field: string) =>
  JSON.stringify([
    field,
    record.sessionId,
    record.sessionClientPublicKeyB64,
    record.sessionServerPublicKeyB64,
    record.createdAt,
  ]);
const encrypt = (record: BoundFields, field: string, value: string | Uint8Array) =>
  aead.encrypt(value, aad(record, field));
const decrypt = (record: BoundFields, field: string, blob: Uint8Array | undefined) =>
  aead.decrypt(blob ?? new Uint8Array(), aad(record, field));

// Item: the bound fields (S, createdAt N), three AES-GCM blobs (B) and expiresAt (N, epoch
// seconds) for the table's TTL, which only deletes within ~48h: getSession() checks expiry itself.
export const storeSession = traced(
  "db.storeSession",
  async (
    sessionId: string,
    sessionServerKeyPair: BoxKeyPair,
    sessionClientPublicKeyB64: string,
    sessionServerJwtChain: string,
    allowedAudienceRoots: string[],
  ) => {
    const bound: BoundFields = {
      sessionId,
      sessionClientPublicKeyB64,
      sessionServerPublicKeyB64: Buffer.from(sessionServerKeyPair.publicKey).toString("base64url"),
      createdAt: Date.now(),
    };

    await client.send(
      new PutItemCommand({
        TableName: DYNAMODB_SESSIONS_TABLE,
        Item: {
          sessionId: { S: sessionId },
          sessionClientPublicKeyB64: { S: bound.sessionClientPublicKeyB64 },
          sessionServerPublicKeyB64: { S: bound.sessionServerPublicKeyB64 },
          createdAt: { N: String(bound.createdAt) },
          expiresAt: { N: String(Math.ceil(bound.createdAt / 1000) + SESSION_TTL_SECONDS) },
          sessionServerPrivateKeyEnc: {
            B: encrypt(bound, "privateKey", sessionServerKeyPair.secretKey),
          },
          sessionServerJwtChainEnc: { B: encrypt(bound, "jwtChain", sessionServerJwtChain) },
          allowedAudienceRootsEnc: {
            B: encrypt(bound, "allowedAudienceRoots", JSON.stringify(allowedAudienceRoots)),
          },
        },
        // No attribute_not_exists: ids are random UUIDs, and an SDK retry of a put that landed
        // would fail the condition and report a stored session as an error.
      }),
    );
  },
);

export const deleteSession = traced("db.deleteSession", async (sessionId: string) => {
  await client.send(
    new DeleteItemCommand({
      TableName: DYNAMODB_SESSIONS_TABLE,
      Key: { sessionId: { S: sessionId } },
    }),
  );
});

export interface Session {
  id: string;
  allowedAudienceRoots: string[];
  sessionClientPublicKey: Uint8Array;
  sessionServerPublicKey: Uint8Array;
  sessionServerPrivateKey: Uint8Array;
  sessionServerJwtChain: string;
}

export const getSession = traced(
  "db.getSession",
  async (sessionId: string): Promise<Session | null> => {
    const { Item } = await client.send(
      new GetItemCommand({
        TableName: DYNAMODB_SESSIONS_TABLE,
        Key: { sessionId: { S: sessionId } },
        ConsistentRead: true,
      }),
    );

    // TTL deletion lags by up to ~48h, so reject expired records here (from the bound createdAt).
    const createdAt = Number(Item?.createdAt?.N ?? 0);
    if (!Item || createdAt + SESSION_TTL_SECONDS * 1000 < Date.now()) {
      return null;
    }

    const bound: BoundFields = {
      sessionId,
      sessionClientPublicKeyB64: Item.sessionClientPublicKeyB64?.S ?? "",
      sessionServerPublicKeyB64: Item.sessionServerPublicKeyB64?.S ?? "",
      createdAt,
    };

    return {
      id: sessionId,
      allowedAudienceRoots: JSON.parse(
        decrypt(bound, "allowedAudienceRoots", Item.allowedAudienceRootsEnc?.B).toString(),
      ),
      sessionClientPublicKey: Buffer.from(bound.sessionClientPublicKeyB64, "base64url"),
      sessionServerPrivateKey: decrypt(bound, "privateKey", Item.sessionServerPrivateKeyEnc?.B),
      sessionServerPublicKey: Buffer.from(bound.sessionServerPublicKeyB64, "base64url"),
      sessionServerJwtChain: decrypt(
        bound,
        "jwtChain",
        Item.sessionServerJwtChainEnc?.B,
      ).toString(),
    };
  },
);

/**
 * Deletes every session past its expiresAt; returns how many. The table's TTL only deletes
 * within ~48h, and expired records hold encrypted private keys. Run by index.ts every 30 min.
 * Nothing is decrypted, and deleting an item that is already gone is a no-op.
 */
export const purgeExpiredSessions = traced("db.purgeExpiredSessions", async () => {
  const now = { ":now": { N: String(Math.floor(Date.now() / 1000)) } };
  let deleted = 0;
  let startKey: Record<string, AttributeValue> | undefined;
  do {
    const page = await client.send(
      new ScanCommand({
        TableName: DYNAMODB_SESSIONS_TABLE,
        ProjectionExpression: "sessionId",
        FilterExpression: "expiresAt < :now",
        ExpressionAttributeValues: now,
        ExclusiveStartKey: startKey,
      }),
    );
    for (const { sessionId } of page.Items ?? []) {
      if (!sessionId) continue;
      await client.send(
        new DeleteItemCommand({ TableName: DYNAMODB_SESSIONS_TABLE, Key: { sessionId } }),
      );
      deleted++;
    }
    startKey = page.LastEvaluatedKey;
  } while (startKey);
  return deleted;
});
