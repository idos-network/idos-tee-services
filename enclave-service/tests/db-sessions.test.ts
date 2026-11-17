import { Binary } from "mongodb";
import { describe, expect, it, vi } from "vitest";
import { keyPair } from "../providers/box.ts";

// In-memory Mongo with the real Binary, so blobs can be inspected and swapped between records.
const h = vi.hoisted(() => {
  const docs = new Map<string, Record<string, unknown>>();
  return {
    docs,
    collection: {
      createIndex: async () => {},
      insertOne: async (doc: Record<string, unknown>) => {
        docs.set(doc.sessionId as string, doc);
      },
      findOne: async ({ sessionId }: { sessionId: string }) => docs.get(sessionId) ?? null,
      deleteOne: async ({ sessionId }: { sessionId: string }) => {
        docs.delete(sessionId);
      },
    },
  };
});

vi.mock("mongodb", async (importOriginal) => ({
  ...(await importOriginal<typeof import("mongodb")>()),
  MongoClient: class {
    connect = async () => {};
    db = () => ({ collection: () => h.collection });
  },
}));

const { getSession, storeSession } = await import("../providers/db.ts");

const store = (id: string, pair = keyPair()) =>
  storeSession(id, pair, "client-pub", "jwt.chain.secret", ["https://aud.example"]);

function doc(id: string) {
  const d = h.docs.get(id);
  if (!d) throw new Error("record missing");
  return d;
}

describe("session records in Mongo", () => {
  it("round-trips a session without plaintext secrets in the record", async () => {
    const pair = keyPair();
    await store("s-1", pair);

    expect(JSON.stringify(doc("s-1"))).not.toContain("jwt.chain.secret");
    for (const field of ["sessionServerPrivateKeyEnc", "sessionServerJwtChainEnc"]) {
      expect(Buffer.from((doc("s-1")[field] as Binary).value()).toString()).not.toContain("jwt");
    }

    const session = await getSession("s-1");
    expect(Buffer.from(session?.sessionServerPrivateKey ?? [])).toEqual(
      Buffer.from(pair.secretKey),
    );
    expect(session?.sessionServerJwtChain).toBe("jwt.chain.secret");
    expect(session?.allowedAudienceRoots).toEqual(["https://aud.example"]);
  });

  it("rejects a private key blob copied from another session", async () => {
    await store("victim");
    await store("attacker");
    doc("attacker").sessionServerPrivateKeyEnc = doc("victim").sessionServerPrivateKeyEnc;

    await expect(getSession("attacker")).rejects.toThrow(/authenticate/);
  });

  it("rejects a tampered blob", async () => {
    await store("s-2");
    const bytes = Buffer.from((doc("s-2").sessionServerJwtChainEnc as Binary).value());
    bytes.writeUInt8(bytes.readUInt8(20) ^ 1, 20);
    doc("s-2").sessionServerJwtChainEnc = new Binary(bytes);

    await expect(getSession("s-2")).rejects.toThrow(/authenticate/);
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["short", Buffer.alloc(32).toString("base64")],
  ])("refuses to load with a %s master key", async (_name, key) => {
    const original = process.env.FLE_MASTER_KEY;
    try {
      if (key === undefined) delete process.env.FLE_MASTER_KEY;
      else process.env.FLE_MASTER_KEY = key;
      vi.resetModules();
      await expect(import("../providers/db.ts")).rejects.toThrow(/96 bytes/);
    } finally {
      process.env.FLE_MASTER_KEY = original;
    }
  });
});
