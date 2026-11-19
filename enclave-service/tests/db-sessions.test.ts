import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { createAesGcm } from "@idos/tee-common/aes-gcm.ts";
import { Binary } from "mongodb";
import { describe, expect, it, onTestFinished, vi } from "vitest";
import { keyPair } from "../providers/box.ts";

type Item = Record<string, AttributeValue>;

// In-memory DynamoDB table keyed by sessionId, so blobs can be inspected and swapped between
// records, and an in-memory Mongo collection for scripts/migrate-sessions.ts.
const h = vi.hoisted(() => ({
  items: new Map<string, Item>(),
  mongoDocs: [] as Record<string, unknown>[],
}));

vi.mock("@aws-sdk/client-dynamodb", async (importOriginal) => {
  const real = await importOriginal<typeof import("@aws-sdk/client-dynamodb")>();
  const { fakeDynamoDBClient } = await import("@idos/tee-common/dynamodb-fake.ts");
  return { ...real, DynamoDBClient: fakeDynamoDBClient(real, "sessionId", h.items) };
});

vi.mock("mongodb", async (importOriginal) => ({
  ...(await importOriginal<typeof import("mongodb")>()),
  MongoClient: class {
    close = async () => {};
    db = () => ({
      collection: () => ({
        find: ({ createdAt }: { createdAt: { $gt: Date } }) =>
          h.mongoDocs.filter((d) => (d.createdAt as Date) > createdAt.$gt),
      }),
    });
  },
}));

const { deleteSession, getSession, storeSession } = await import("../providers/db.ts");

const store = (id: string, pair = keyPair()) =>
  storeSession(id, pair, "client-pub", "jwt.chain.secret", ["https://aud.example"]);

function item(id: string) {
  const i = h.items.get(id);
  if (!i) throw new Error("record missing");
  return i;
}

describe("session records in DynamoDB", () => {
  it("round-trips a session without plaintext secrets in the record", async () => {
    const pair = keyPair();
    await store("s-1", pair);

    expect(JSON.stringify(item("s-1"))).not.toContain("jwt.chain.secret");
    for (const field of ["sessionServerPrivateKeyEnc", "sessionServerJwtChainEnc"]) {
      expect(Buffer.from(item("s-1")[field]?.B ?? []).toString()).not.toContain("jwt");
    }

    const session = await getSession("s-1");
    expect(Buffer.from(session?.sessionServerPrivateKey ?? [])).toEqual(
      Buffer.from(pair.secretKey),
    );
    expect(session?.sessionServerJwtChain).toBe("jwt.chain.secret");
    expect(session?.allowedAudienceRoots).toEqual(["https://aud.example"]);
  });

  it("sets the TTL attribute an hour after creation, in epoch seconds", async () => {
    await store("s-ttl");

    const { createdAt, expiresAt } = item("s-ttl");
    expect(Number(expiresAt?.N)).toBe(Math.ceil(Number(createdAt?.N) / 1000) + 3600);
  });

  it("returns null for an expired record the TTL has not deleted yet", async () => {
    // Written over an hour ago, so its blobs are bound to that createdAt like a real old record.
    vi.useFakeTimers({ now: Date.now() - 3601_000 });
    try {
      await store("s-old");
    } finally {
      vi.useRealTimers();
    }

    expect(await getSession("s-old")).toBeNull();
  });

  it("deletes a session", async () => {
    await store("s-del");
    await deleteSession("s-del");

    expect(await getSession("s-del")).toBeNull();
  });

  it("rejects a private key blob copied from another session", async () => {
    await store("victim");
    await store("attacker");
    item("attacker").sessionServerPrivateKeyEnc = item("victim")
      .sessionServerPrivateKeyEnc as AttributeValue;

    await expect(getSession("attacker")).rejects.toThrow(/authenticate/);
  });

  it("rejects a tampered blob", async () => {
    await store("s-2");
    const bytes = Buffer.from(item("s-2").sessionServerJwtChainEnc?.B ?? []);
    bytes.writeUInt8(bytes.readUInt8(20) ^ 1, 20);
    item("s-2").sessionServerJwtChainEnc = { B: bytes };

    await expect(getSession("s-2")).rejects.toThrow(/authenticate/);
  });

  it.each([
    ["sessionClientPublicKeyB64", { S: "attacker-pub" }],
    ["sessionServerPublicKeyB64", { S: "attacker-pub" }],
    ["createdAt", { N: String(Date.now() + 1000) }],
  ])("rejects a record whose %s was edited", async (field, value) => {
    h.items.delete("s-edit");
    await store("s-edit");
    item("s-edit")[field] = value;

    await expect(getSession("s-edit")).rejects.toThrow(/authenticate/);
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

describe("scripts/migrate-sessions.ts", () => {
  // A record exactly as the Mongo provider wrote it: Binary blobs, createdAt a Date in the AAD.
  function mongoSession(sessionId: string, createdAt: Date, pair = keyPair()) {
    const aead = createAesGcm(process.env.FLE_MASTER_KEY, "enclave-session-v1");
    const bound = {
      sessionId,
      sessionClientPublicKeyB64: "client-pub",
      sessionServerPublicKeyB64: Buffer.from(pair.publicKey).toString("base64url"),
      createdAt,
    };
    const enc = (field: string, value: string | Uint8Array) =>
      new Binary(
        aead.encrypt(
          value,
          JSON.stringify([
            field,
            bound.sessionId,
            bound.sessionClientPublicKeyB64,
            bound.sessionServerPublicKeyB64,
            bound.createdAt.getTime(),
          ]),
        ),
      );
    return {
      ...bound,
      sessionServerPrivateKeyEnc: enc("privateKey", pair.secretKey),
      sessionServerJwtChainEnc: enc("jwtChain", "mongo.jwt.chain"),
      allowedAudienceRootsEnc: enc("allowedAudienceRoots", JSON.stringify(["https://aud.example"])),
    };
  }

  it("copies live Mongo sessions so the new provider decrypts them, and is idempotent", async () => {
    const originalMongoUri = process.env.MONGO_URI;
    process.env.MONGO_URI = "mongodb://localhost:27017";
    onTestFinished(() => {
      process.env.MONGO_URI = originalMongoUri;
      h.mongoDocs.length = 0;
    });
    const pair = keyPair();
    h.mongoDocs.push(
      mongoSession("m-live", new Date(Date.now() - 60_000), pair),
      mongoSession("m-expired", new Date(Date.now() - 3601_000)),
    );
    // Already migrated by an earlier boot: kept as it is.
    await store("m-again");
    const before = item("m-again");
    h.mongoDocs.push(mongoSession("m-again", new Date()));

    vi.resetModules();
    await import("../scripts/migrate-sessions.ts");

    const session = await getSession("m-live");
    expect(session?.sessionServerJwtChain).toBe("mongo.jwt.chain");
    expect(Buffer.from(session?.sessionServerPrivateKey ?? [])).toEqual(
      Buffer.from(pair.secretKey),
    );
    expect(h.items.has("m-expired")).toBe(false);
    expect(item("m-again")).toBe(before);
  });
});
