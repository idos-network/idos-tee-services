import { randomBytes } from "node:crypto";
import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { describe, expect, it, vi } from "vitest";
import { armBody } from "./helpers.ts";

type Item = Record<string, AttributeValue>;

// In-memory DynamoDB table keyed by armedId, so blobs can be inspected and swapped between records.
// KMS stand-in: the "wrapped" data key is the key plus its KMS key and encryption context, and
// unwrapping fails on a different key or context, as KMS does.
const h = vi.hoisted(() => ({
  items: new Map<string, Item>(),
  kmsDecrypt: vi.fn(
    async (
      wrapped: Uint8Array,
      opts: { keyId?: string; encryptionContext?: Record<string, string> } = {},
    ) => {
      const { key, keyId, armedId } = JSON.parse(Buffer.from(wrapped).toString());
      if (keyId !== opts.keyId) throw new Error("IncorrectKeyException");
      if (armedId !== opts.encryptionContext?.armedId) {
        throw new Error("InvalidCiphertextException");
      }
      return Buffer.from(key, "base64");
    },
  ),
}));

vi.mock("@idos/nitro-nsm/kms-decrypt.ts", async () => {
  const { randomBytes } = await import("node:crypto");
  return {
    kmsDecrypt: h.kmsDecrypt,
    kmsGenerateDataKey: async (keyId: string, { armedId }: Record<string, string>) => {
      const plaintext = randomBytes(32);
      const wrapped = { key: plaintext.toString("base64"), keyId, armedId };
      return { plaintext, ciphertext: Buffer.from(JSON.stringify(wrapped)) };
    },
  };
});

vi.mock("@aws-sdk/client-dynamodb", async (importOriginal) => {
  const real = await importOriginal<typeof import("@aws-sdk/client-dynamodb")>();
  const { fakeDynamoDBClient } = await import("@idos/tee-common/dynamodb-fake.ts");
  return { ...real, DynamoDBClient: fakeDynamoDBClient(real, "armedId", h.items) };
});

const { deleteArmed, getArmed, storeArmed } = await import("../providers/db.ts");
const { encryptGcm } = await import("@idos/tee-common/aes-gcm.ts");

// The plaintext data key inside a stand-in wrapped key, as if it had leaked.
const leakedKey = (wrapped: AttributeValue | undefined) =>
  Buffer.from(JSON.parse(Buffer.from(wrapped?.B ?? []).toString()).key, "base64");

function item(id: string) {
  const i = h.items.get(id);
  if (!i) throw new Error("record missing");
  return i;
}

describe("armed records in DynamoDB", () => {
  it("stores everything but the id as one encrypted blob", async () => {
    await storeArmed("id-1", armBody());

    const { dataEnc, dataKeyEnc, ...plaintext } = item("id-1");
    expect(dataEnc?.B).toBeDefined();
    expect(dataKeyEnc?.B).toBeDefined();
    expect(Object.keys(plaintext).sort()).toEqual(["armedId", "createdAt"]);
    expect(JSON.stringify(plaintext)).not.toContain("iron-secret");
    expect(Buffer.from(dataEnc?.B ?? []).toString()).not.toContain("iron-secret");
  });

  it("round-trips the armed record", async () => {
    await storeArmed("id-2", armBody());

    const armed = await getArmed("id-2");
    expect(armed).toEqual({ id: "id-2", ...armBody() });
  });

  it("rejects a blob copied from another record", async () => {
    await storeArmed("victim", armBody());
    await storeArmed("attacker", armBody({ environment: "production" }));
    item("attacker").dataEnc = item("victim").dataEnc as AttributeValue;

    await expect(getArmed("attacker")).rejects.toThrow(/authenticate/);

    // ...and with its data key too: KMS refuses the key under another armedId's context
    item("attacker").dataKeyEnc = item("victim").dataKeyEnc as AttributeValue;
    await expect(getArmed("attacker")).rejects.toThrow(/InvalidCiphertext/);
  });

  it("unwraps each data key once across concurrent and repeated reads", async () => {
    await storeArmed("id-5", armBody());
    h.kmsDecrypt.mockClear();

    await Promise.all(Array.from({ length: 20 }, () => getArmed("id-5")));
    await getArmed("id-5");

    expect(h.kmsDecrypt).toHaveBeenCalledTimes(1);
  });

  it("asks KMS again after a failed unwrap", async () => {
    await storeArmed("id-6", armBody());
    h.kmsDecrypt.mockClear();
    h.kmsDecrypt.mockRejectedValueOnce(new Error("ThrottlingException"));

    await expect(getArmed("id-6")).rejects.toThrow(/Throttling/);
    expect(await getArmed("id-6")).toEqual({ id: "id-6", ...armBody() });
    expect(h.kmsDecrypt).toHaveBeenCalledTimes(2);
  });

  it("rejects a tampered blob", async () => {
    await storeArmed("id-4", armBody());

    const bytes = Buffer.from(item("id-4").dataEnc?.B ?? []);
    bytes.writeUInt8(bytes.readUInt8(20) ^ 1, 20);
    item("id-4").dataEnc = { B: bytes };

    await expect(getArmed("id-4")).rejects.toThrow(/authenticate/);
  });

  it("deletes a record, and deleting it again succeeds", async () => {
    await storeArmed("id-3", armBody());

    await deleteArmed("id-3");
    expect(await getArmed("id-3")).toBeNull();
    await expect(deleteArmed("id-3")).resolves.toBeUndefined();
  });

  it("never decrypts a record with another record's cached key", async () => {
    await storeArmed("leaked", armBody());
    await storeArmed("target", armBody());
    await getArmed("leaked"); // its key is now cached

    // A table writer who knows the leaked key forges "target" under it, with the right AAD
    const forged = encryptGcm(
      leakedKey(item("leaked").dataKeyEnc),
      JSON.stringify(armBody({ environment: "production" })),
      "target",
    );
    item("target").dataKeyEnc = item("leaked").dataKeyEnc as AttributeValue;
    item("target").dataEnc = { B: forged };

    await expect(getArmed("target")).rejects.toThrow(/InvalidCiphertext/);
  });

  it("pins the armed KMS key on unwrap", async () => {
    await storeArmed("id-7", armBody());
    // e.g. a key the host can encrypt under, with the right context
    const foreign = { key: randomBytes(32).toString("base64"), keyId: "luks", armedId: "id-7" };
    item("id-7").dataKeyEnc = { B: Buffer.from(JSON.stringify(foreign)) };

    await expect(getArmed("id-7")).rejects.toThrow(/IncorrectKey/);
    expect(h.kmsDecrypt).toHaveBeenLastCalledWith(expect.anything(), {
      keyId: process.env.AWS_KMS_ARMED_ARN,
      encryptionContext: { armedId: "id-7" },
    });
  });

  it("evicts a cached key on disarm and after the TTL", async () => {
    vi.useFakeTimers();
    try {
      await storeArmed("id-8", armBody());
      const stored = { ...item("id-8") };
      h.kmsDecrypt.mockClear();

      await getArmed("id-8");
      vi.advanceTimersByTime(10 * 60 * 1000);
      await getArmed("id-8");
      expect(h.kmsDecrypt).toHaveBeenCalledTimes(2);

      await deleteArmed("id-8");
      h.items.set("id-8", stored); // same record back: the key must come from KMS again
      await getArmed("id-8");
      expect(h.kmsDecrypt).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses to load without AWS_KMS_ARMED_ARN", async () => {
    const original = process.env.AWS_KMS_ARMED_ARN;
    try {
      delete process.env.AWS_KMS_ARMED_ARN;
      vi.resetModules();
      await expect(import("../providers/db.ts")).rejects.toThrow(/AWS_KMS_ARMED_ARN/);
    } finally {
      process.env.AWS_KMS_ARMED_ARN = original;
    }
  });
});
