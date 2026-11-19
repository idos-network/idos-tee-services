import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { describe, expect, it, vi } from "vitest";
import { keyPair } from "../providers/box.ts";

type Item = Record<string, AttributeValue>;

// In-memory DynamoDB table keyed by sessionId, so blobs can be inspected and swapped between records.
const h = vi.hoisted(() => ({ items: new Map<string, Item>() }));

vi.mock("@aws-sdk/client-dynamodb", async (importOriginal) => {
  const real = await importOriginal<typeof import("@aws-sdk/client-dynamodb")>();
  const { fakeDynamoDBClient } = await import("@idos/tee-common/dynamodb-fake.ts");
  return { ...real, DynamoDBClient: fakeDynamoDBClient(real, "sessionId", h.items) };
});

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
