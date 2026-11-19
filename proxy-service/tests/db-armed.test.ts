import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { describe, expect, it, vi } from "vitest";
import { armBody } from "./helpers.ts";

type Item = Record<string, AttributeValue>;

// In-memory DynamoDB table keyed by armedId, so blobs can be inspected and swapped between records.
const h = vi.hoisted(() => ({ items: new Map<string, Item>() }));

vi.mock("@aws-sdk/client-dynamodb", async (importOriginal) => {
  const real = await importOriginal<typeof import("@aws-sdk/client-dynamodb")>();
  const conditionFailed = () =>
    new real.ConditionalCheckFailedException({ message: "condition failed", $metadata: {} });

  class DynamoDBClient {
    async send(command: { input: { Key?: Item; Item?: Item; ConditionExpression?: string } }) {
      const { input } = command;
      const id = (input.Key ?? input.Item)?.armedId?.S as string;
      const exists = h.items.has(id);
      if (command instanceof real.PutItemCommand) {
        if (input.ConditionExpression?.includes("attribute_not_exists") && exists) {
          throw conditionFailed();
        }
        h.items.set(id, input.Item as Item);
        return {};
      }
      if (command instanceof real.GetItemCommand) return { Item: h.items.get(id) };
      if (command instanceof real.DeleteItemCommand) {
        if (input.ConditionExpression?.includes("attribute_exists") && !exists) {
          throw conditionFailed();
        }
        h.items.delete(id);
        return {};
      }
      throw new Error("unexpected command");
    }
  }

  return { ...real, DynamoDBClient };
});

const { deleteArmed, getArmed, storeArmed } = await import("../providers/db.ts");

function item(id: string) {
  const i = h.items.get(id);
  if (!i) throw new Error("record missing");
  return i;
}

describe("armed records in DynamoDB", () => {
  it("stores everything but the id as one encrypted blob", async () => {
    await storeArmed("id-1", armBody());

    const { dataEnc, ...plaintext } = item("id-1");
    expect(dataEnc?.B).toBeDefined();
    expect(Object.keys(plaintext).sort()).toEqual(["armedId", "createdAt"]);
    expect(JSON.stringify(plaintext)).not.toContain("iron-secret");
    expect(Buffer.from(dataEnc?.B ?? []).toString()).not.toContain("iron-secret");
  });

  it("round-trips the armed record", async () => {
    await storeArmed("id-2", armBody());

    const armed = await getArmed("id-2");
    expect(armed).toEqual({ id: "id-2", ...armBody() });
  });

  it("never overwrites an existing record", async () => {
    await storeArmed("id-5", armBody());

    await expect(storeArmed("id-5", armBody({ environment: "production" }))).rejects.toThrow(
      /condition/,
    );
    expect(await getArmed("id-5")).toEqual({ id: "id-5", ...armBody() });
  });

  it("rejects a blob copied from another record", async () => {
    await storeArmed("victim", armBody());
    await storeArmed("attacker", armBody({ environment: "production" }));
    item("attacker").dataEnc = item("victim").dataEnc as AttributeValue;

    await expect(getArmed("attacker")).rejects.toThrow(/armedId/);
  });

  it("rejects a tampered blob", async () => {
    await storeArmed("id-4", armBody());

    const bytes = Buffer.from(item("id-4").dataEnc?.B ?? []);
    bytes.writeUInt8(bytes.readUInt8(20) ^ 1, 20);
    item("id-4").dataEnc = { B: bytes };

    await expect(getArmed("id-4")).rejects.toThrow(/authenticate/);
  });

  it("deletes a record and reports whether it existed", async () => {
    await storeArmed("id-3", armBody());

    expect(await deleteArmed("id-3")).toBe(true);
    expect(await getArmed("id-3")).toBeNull();
    expect(await deleteArmed("id-3")).toBe(false);
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
