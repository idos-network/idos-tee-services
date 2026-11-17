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

// The AAD binds each blob to its session and field, so a Mongo writer can't swap blobs.
const encrypt = (sessionId: string, field: string, value: string | Uint8Array) =>
  new Binary(aead.encrypt(value, `${sessionId}/${field}`));
const decrypt = (sessionId: string, field: string, blob: Binary) =>
  aead.decrypt(blob.value(), `${sessionId}/${field}`);

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

    const record: SessionRecordDocument = {
      sessionId,
      sessionServerPrivateKeyEnc: encrypt(sessionId, "privateKey", sessionServerKeyPair.secretKey),
      sessionServerPublicKeyB64: Buffer.from(sessionServerKeyPair.publicKey).toString("base64url"),
      sessionClientPublicKeyB64,
      sessionServerJwtChainEnc: encrypt(sessionId, "jwtChain", sessionServerJwtChain),
      allowedAudienceRootsEnc: encrypt(
        sessionId,
        "allowedAudienceRoots",
        JSON.stringify(allowedAudienceRoots),
      ),
      createdAt: new Date(),
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
        decrypt(sessionId, "allowedAudienceRoots", session.allowedAudienceRootsEnc).toString(),
      ),
      sessionClientPublicKey: Buffer.from(session.sessionClientPublicKeyB64, "base64url"),
      sessionServerPrivateKey: decrypt(sessionId, "privateKey", session.sessionServerPrivateKeyEnc),
      sessionServerPublicKey: Buffer.from(session.sessionServerPublicKeyB64, "base64url"),
      sessionServerJwtChain: decrypt(
        sessionId,
        "jwtChain",
        session.sessionServerJwtChainEnc,
      ).toString(),
    };
  },
);
