import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { traced } from "@idos/tee-common/telemetry.ts";
import { Binary, type Db, MongoClient } from "mongodb";
import { DB_ARMED_COLLECTION, DB_NAME, FLE_MASTER_KEY, MONGO_URI } from "../env.ts";
import type { ArmRequest } from "../utils/dto.ts";

let db: Db | null = null;

const client = new MongoClient(MONGO_URI, {
  maxPoolSize: 40,
  wtimeoutMS: 2500,
});

// AES-256-GCM key derived from the master key, which scripts/run.ash decrypts with attestation.
const DATA_KEY = Buffer.from(
  hkdfSync("sha256", Buffer.from(FLE_MASTER_KEY, "base64"), "", "proxy-armed-v1", 32),
);
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** iv ‖ ciphertext ‖ tag */
function encrypt(plaintext: string): Binary {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", DATA_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return new Binary(Buffer.concat([iv, ciphertext, cipher.getAuthTag()]));
}

function decrypt(blob: Binary): string {
  const bytes = blob.value();
  if (bytes.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error("Encrypted blob is too short");
  }
  const decipher = createDecipheriv("aes-256-gcm", DATA_KEY, bytes.subarray(0, IV_LENGTH));
  decipher.setAuthTag(bytes.subarray(bytes.length - TAG_LENGTH));
  return Buffer.concat([
    decipher.update(bytes.subarray(IV_LENGTH, bytes.length - TAG_LENGTH)),
    decipher.final(),
  ]).toString("utf8");
}

export async function connectDB() {
  if (!db) {
    await client.connect();
    db = client.db(DB_NAME);
    // getArmed() looks records up by armedId on every proxy call.
    await db.collection(DB_ARMED_COLLECTION).createIndex({ armedId: 1 }, { unique: true });
  }

  return db;
}

export interface ArmedRecordDocument {
  armedId: string;
  // Everything (incl. the armedId) in one AES-GCM blob, so a Mongo
  // writer can neither swap the host key / environment nor copy a blob between records.
  dataEnc: Binary;
  createdAt: Date;
}

export type Armed = ArmRequest & { id: string };

export const storeArmed = traced("db.storeArmed", async (armedId: string, data: ArmRequest) => {
  const db = await connectDB();

  const record: ArmedRecordDocument = {
    armedId,
    dataEnc: encrypt(JSON.stringify({ armedId, ...data })),
    createdAt: new Date(),
  };

  await db.collection(DB_ARMED_COLLECTION).insertOne(record);
});

export const getArmed = traced("db.getArmed", async (armedId: string): Promise<Armed | null> => {
  const db = await connectDB();

  const record = await db.collection<ArmedRecordDocument>(DB_ARMED_COLLECTION).findOne({ armedId });

  if (!record) {
    return null;
  }

  const { armedId: blobArmedId, ...data }: ArmRequest & { armedId: string } = JSON.parse(
    decrypt(record.dataEnc),
  );

  if (blobArmedId !== armedId) {
    throw new Error(`Armed record ${armedId} holds a blob for armedId ${blobArmedId}`);
  }

  return { id: armedId, ...data };
});

/** True when a record was deleted, false when there was none. */
export const deleteArmed = traced("db.deleteArmed", async (armedId: string): Promise<boolean> => {
  const db = await connectDB();
  const { deletedCount } = await db.collection(DB_ARMED_COLLECTION).deleteOne({ armedId });
  return deletedCount === 1;
});
