// One-off copy of live sessions from Mongo (enclave.idOSEnclave) to DynamoDB, run by
// scripts/run.ash before the service starts while config.env still has MONGO_URI.
// Blobs are copied as they are: same master key and AAD (createdAt as epoch ms, see
// providers/db.ts), so nothing is decrypted here. Idempotent: items already in the table are
// kept, and once Mongo only holds expired sessions it copies nothing.
// shortcut: delete this script, its run.ash step and the mongodb dependency once every
// environment has booted with DynamoDB.
import {
  ConditionalCheckFailedException,
  DynamoDBClient,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { type Binary, MongoClient } from "mongodb";
import { DYNAMODB_SESSIONS_TABLE, SESSION_TTL_SECONDS } from "../env.ts";

interface MongoSession {
  sessionId: string;
  sessionClientPublicKeyB64: string;
  sessionServerPublicKeyB64: string;
  sessionServerPrivateKeyEnc: Binary;
  sessionServerJwtChainEnc: Binary;
  allowedAudienceRootsEnc: Binary;
  createdAt: Date;
}

// biome-ignore lint/style/noNonNullAssertion: run.ash only runs this with MONGO_URI set
const mongo = new MongoClient(process.env.MONGO_URI!);
// Same endpoint as providers/db.ts: only dynamodb.<region> is mapped through vsock.
const dynamo = new DynamoDBClient({ accountIdEndpointMode: "disabled" });

try {
  const since = new Date(Date.now() - SESSION_TTL_SECONDS * 1000);
  const live = mongo
    .db("enclave")
    .collection<MongoSession>("idOSEnclave")
    .find({ createdAt: { $gt: since } });

  let copied = 0;
  let kept = 0;
  for await (const s of live) {
    const createdAt = s.createdAt.getTime();
    try {
      await dynamo.send(
        new PutItemCommand({
          TableName: DYNAMODB_SESSIONS_TABLE,
          Item: {
            sessionId: { S: s.sessionId },
            sessionClientPublicKeyB64: { S: s.sessionClientPublicKeyB64 },
            sessionServerPublicKeyB64: { S: s.sessionServerPublicKeyB64 },
            createdAt: { N: String(createdAt) },
            expiresAt: { N: String(Math.ceil(createdAt / 1000) + SESSION_TTL_SECONDS) },
            sessionServerPrivateKeyEnc: { B: s.sessionServerPrivateKeyEnc.value() },
            sessionServerJwtChainEnc: { B: s.sessionServerJwtChainEnc.value() },
            allowedAudienceRootsEnc: { B: s.allowedAudienceRootsEnc.value() },
          },
          ConditionExpression: "attribute_not_exists(sessionId)",
        }),
      );
      copied++;
    } catch (error) {
      if (!(error instanceof ConditionalCheckFailedException)) throw error;
      kept++;
    }
  }

  console.log(
    `Session migration: ${copied} copied from Mongo to ${DYNAMODB_SESSIONS_TABLE}, ${kept} already there`,
  );
} finally {
  await mongo.close();
}
