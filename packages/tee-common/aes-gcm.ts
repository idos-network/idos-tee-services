// AES-256-GCM for fields stored in the database: under a key derived from the attested 96-byte
// master key (createAesGcm, FLE_MASTER_KEY from scripts/run.ash) or under a given data key.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** iv ‖ ciphertext ‖ tag under a 32-byte key; `aad` binds the blob to its record. */
export function encryptGcm(key: Uint8Array, plaintext: string | Uint8Array, aad = ""): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv).setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

export function decryptGcm(key: Uint8Array, bytes: Uint8Array, aad = ""): Buffer {
  if (bytes.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error("Encrypted blob is too short");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, IV_LENGTH));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(bytes.subarray(bytes.length - TAG_LENGTH));
  return Buffer.concat([
    decipher.update(bytes.subarray(IV_LENGTH, bytes.length - TAG_LENGTH)),
    decipher.final(),
  ]);
}

/** `info` separates the derived key per use, `aad` binds a blob to its record. */
export function createAesGcm(masterKeyB64: string | undefined, info: string) {
  // An empty or truncated key would derive the same key in every deployment: fail at boot.
  const masterKey = Buffer.from(masterKeyB64 ?? "", "base64");
  if (masterKey.length !== 96) {
    throw new Error("FLE_MASTER_KEY must decode to 96 bytes");
  }
  const key = Buffer.from(hkdfSync("sha256", masterKey, "", info, 32));

  return {
    encrypt: (plaintext: string | Uint8Array, aad = "") => encryptGcm(key, plaintext, aad),
    decrypt: (bytes: Uint8Array, aad = "") => decryptGcm(key, bytes, aad),
  };
}
