import { createAesGcm } from "@idos/tee-common/aes-gcm.ts";
import { getLogger } from "@idos/tee-common/logger.ts";
import { traced } from "@idos/tee-common/telemetry.ts";
import { Binary, type Db, MongoClient } from "mongodb";
import type { BoxKeyPair } from "tweetnacl";
import {
  DB_ENCLAVE_COLLECTION,
  DB_NAME,
  FLE_MASTER_KEY,
  MONGO_URI,
  SESSION_TTL_SECONDS,
} from "../env.ts";

let db: Db | null = null;

const client = new MongoClient(MONGO_URI, {
  maxPoolSize: 40,
  wtimeoutMS: 2500,
});

// Key derived from the master key, which scripts/run.ash decrypts with attestation.
const aead = createAesGcm(FLE_MASTER_KEY, "enclave-session-v1");

// The record's plaintext fields a Mongo writer could otherwise swap or edit (the client key
// authenticates the session, createdAt sets its expiry).
type BoundFields = Pick<
  SessionRecordDocument,
  "sessionId" | "sessionClientPublicKeyB64" | "sessionServerPublicKeyB64" | "createdAt"
>;

// The AAD binds each blob to its field and to the record's plaintext fields: changing any of
// them, or moving a blob to another session or field, fails decryption.
const aad = (record: BoundFields, field: string) =>
  JSON.stringify([
    field,
    record.sessionId,
    record.sessionClientPublicKeyB64,
    record.sessionServerPublicKeyB64,
    record.createdAt.getTime(),
  ]);
const encrypt = (record: BoundFields, field: string, value: string | Uint8Array) =>
  new Binary(aead.encrypt(value, aad(record, field)));
const decrypt = (record: BoundFields, field: string, blob: Binary) =>
  aead.decrypt(blob.value(), aad(record, field));

export async function connectDB() {
  if (!db) {
    await client.connect();
    const sessions = client.db(DB_NAME).collection(DB_ENCLAVE_COLLECTION);
    await Promise.all([
      sessions.createIndex({ sessionId: 1 }, { unique: true }),
      // Mongo's TTL monitor deletes expired session records (incl. encrypted private keys).
      sessions.createIndex({ createdAt: 1 }, { expireAfterSeconds: SESSION_TTL_SECONDS }),
    ]);
    db = client.db(DB_NAME);

    // getSession() looks sessions up by sessionId on every public-key/decrypt
    // call; without an index that is a full collection scan. Idempotent, and
    // not awaited: a failed build only costs speed, so log it and keep serving.
    db.collection(DB_ENCLAVE_COLLECTION)
      .createIndex({ sessionId: 1 }, { unique: true })
      .catch((error) => getLogger().error({ error: String(error) }, "sessionId index failed"));
  }

  return db;
}

export interface SessionRecordDocument {
  sessionId: string;
  sessionClientPublicKeyB64: string;
  sessionServerPublicKeyB64: string;
  sessionServerPrivateKeyEnc: Binary;
  sessionServerJwtChainEnc: Binary;
  allowedAudienceRootsEnc: Binary;
  createdAt: Date;
}

export const storeSession = traced(
  "db.storeSession",
  async (
    sessionId: string,
    sessionServerKeyPair: BoxKeyPair,
    sessionClientPublicKeyB64: string,
    sessionServerJwtChain: string,
    allowedAudienceRoots: string[],
  ) => {
    const db = await connectDB();

    const bound: BoundFields = {
      sessionId,
      sessionClientPublicKeyB64,
      sessionServerPublicKeyB64: Buffer.from(sessionServerKeyPair.publicKey).toString("base64url"),
      createdAt: new Date(),
    };

    const record: SessionRecordDocument = {
      ...bound,
      sessionServerPrivateKeyEnc: encrypt(bound, "privateKey", sessionServerKeyPair.secretKey),
      sessionServerJwtChainEnc: encrypt(bound, "jwtChain", sessionServerJwtChain),
      allowedAudienceRootsEnc: encrypt(
        bound,
        "allowedAudienceRoots",
        JSON.stringify(allowedAudienceRoots),
      ),
    };

    await db.collection(DB_ENCLAVE_COLLECTION).insertOne(record);
  },
);

export const deleteSession = traced("db.deleteSession", async (sessionId: string) => {
  const db = await connectDB();
  await db.collection(DB_ENCLAVE_COLLECTION).deleteOne({ sessionId });
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
    const db = await connectDB();

    const session = await db
      .collection<SessionRecordDocument>(DB_ENCLAVE_COLLECTION)
      .findOne({ sessionId });

    // The TTL monitor runs ~every 60s, so also reject expired records (and legacy ones without createdAt).
    const expiresAt = (session?.createdAt?.getTime() ?? 0) + SESSION_TTL_SECONDS * 1000;
    if (!session || expiresAt < Date.now()) {
      return null;
    }

    return {
      id: sessionId,
      allowedAudienceRoots: JSON.parse(
        decrypt(session, "allowedAudienceRoots", session.allowedAudienceRootsEnc).toString(),
      ),
      sessionClientPublicKey: Buffer.from(session.sessionClientPublicKeyB64, "base64url"),
      sessionServerPrivateKey: decrypt(session, "privateKey", session.sessionServerPrivateKeyEnc),
      sessionServerPublicKey: Buffer.from(session.sessionServerPublicKeyB64, "base64url"),
      sessionServerJwtChain: decrypt(
        session,
        "jwtChain",
        session.sessionServerJwtChainEnc,
      ).toString(),
    };
  },
);
