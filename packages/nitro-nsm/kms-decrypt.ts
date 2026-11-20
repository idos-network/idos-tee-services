import { execFileSync } from "node:child_process";
import { generateKeyPair, type KeyObject } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { getAttestationDocument } from "./index.ts";

/**
 * Opens KMS's CiphertextForRecipient: CMS EnvelopedData (BER) holding an AES-256-CBC key
 * wrapped with RSA-OAEP-SHA256 for the public key of the attestation document.
 */
export function unwrapEnvelope(envelope: Uint8Array, privateKey: KeyObject): Buffer {
  // openssl only reads the key from a file (Node's stdin pipe is a socket, /dev/stdin can't
  // be reopened). The key is single-use and the directory is 0700 in enclave RAM.
  const dir = mkdtempSync(join(tmpdir(), "kms-"));
  try {
    const keyFile = join(dir, "key.pem");
    writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

    return execFileSync(
      "openssl",
      ["cms", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFile],
      { input: envelope },
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// Without the NSM addon (local runs, entropy/facesign images) KMS answers in plaintext to the
// host role; inside our enclaves the addon is always there.
const hasNsm = existsSync(new URL("./nitro-nsm.node", import.meta.url));

// The SDK sets no timeouts: without them a stalled vsock connection hangs the caller.
const kms = new KMSClient({
  requestHandler: { connectionTimeout: 1_000, requestTimeout: 3_000, throwOnRequestTimeout: true },
});

/**
 * Recipient for a KMS call whose answer only this enclave can read: the enclave's attestation
 * document carrying a fresh RSA key. KMS checks the hypervisor's signature, lets the key policy
 * require the EIF's PCRs (kms:RecipientAttestation:PCR0-2) and returns no plaintext, only
 * CiphertextForRecipient encrypted to that key. The host's instance-role credentials still sign
 * the call, but are useless without the attestation.
 */
async function recipient() {
  const { publicKey, privateKey } = await promisify(generateKeyPair)("rsa", {
    modulusLength: 2048,
  });

  return {
    Recipient: {
      KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256" as const,
      AttestationDocument: getAttestationDocument({
        publicKey: publicKey.export({ type: "spki", format: "der" }),
      }),
    },
    open(CiphertextForRecipient?: Uint8Array): Buffer {
      if (!CiphertextForRecipient) {
        throw new Error("KMS returned no CiphertextForRecipient");
      }
      return unwrapEnvelope(CiphertextForRecipient, privateKey);
    },
  };
}

/** KMS Decrypt, with this enclave's attestation as Recipient where the NSM exists. */
export async function kmsDecrypt(
  ciphertext: Uint8Array,
  encryptionContext?: Record<string, string>,
): Promise<Buffer> {
  const input = { CiphertextBlob: ciphertext, EncryptionContext: encryptionContext };
  if (!hasNsm) {
    return Buffer.from((await kms.send(new DecryptCommand(input))).Plaintext as Uint8Array);
  }

  const { Recipient, open } = await recipient();
  const { CiphertextForRecipient } = await kms.send(new DecryptCommand({ ...input, Recipient }));
  return open(CiphertextForRecipient);
}

/**
 * A fresh AES-256 data key: `plaintext` for this enclave only, `ciphertext` wrapped by `keyId`
 * and bound to `encryptionContext`, to store next to what the key encrypts.
 */
export async function kmsGenerateDataKey(
  keyId: string,
  encryptionContext: Record<string, string>,
): Promise<{ plaintext: Buffer; ciphertext: Uint8Array }> {
  const input = { KeyId: keyId, KeySpec: "AES_256" as const, EncryptionContext: encryptionContext };
  if (!hasNsm) {
    const { Plaintext, CiphertextBlob } = await kms.send(new GenerateDataKeyCommand(input));
    return {
      plaintext: Buffer.from(Plaintext as Uint8Array),
      ciphertext: CiphertextBlob as Uint8Array,
    };
  }

  const { Recipient, open } = await recipient();
  const { CiphertextForRecipient, CiphertextBlob } = await kms.send(
    new GenerateDataKeyCommand({ ...input, Recipient }),
  );
  if (!CiphertextBlob) {
    throw new Error("KMS returned no CiphertextBlob");
  }
  return { plaintext: open(CiphertextForRecipient), ciphertext: CiphertextBlob };
}
