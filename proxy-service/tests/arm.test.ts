import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { app, arm, armed, deleteArmed, resetMocks, storeArmed } from "./app.ts";
import { ARM_TOKEN, armBody, hostJws, IDENTITY_KEY } from "./helpers.ts";

describe("POST /arm", () => {
  beforeEach(resetMocks);

  it("rejects a missing arm token", async () => {
    await request(app).post("/arm").send(armBody()).expect(401);
    expect(storeArmed()).not.toHaveBeenCalled();
  });

  it("rejects an unknown arm token", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", "Bearer not-an-arm-token")
      .send(armBody())
      .expect(401);
    expect(storeArmed()).not.toHaveBeenCalled();
  });

  it("accepts any token from ARM_TOKENS", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", "Bearer arm-token-one")
      .send(armBody())
      .expect(200);
  });

  it("rejects an invalid body", async () => {
    const res = await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send({ ...armBody(), allow: [] })
      .expect(400);

    expect(res.body.error).toBe("Invalid request body");
    expect(storeArmed()).not.toHaveBeenCalled();
  });

  it("rejects an unknown api", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send({ ...armBody(), api: "kraken" })
      .expect(400);
  });

  it("rejects iron auth without an api key", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send({ ...armBody(), auth: {} })
      .expect(400);
  });

  it("rejects a kalshi private key that is not a PEM", async () => {
    const res = await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ api: "kalshi", auth: { apiKeyId: "key-1", privateKeyPem: "nope" } }))
      .expect(400);

    expect(res.body.details).toEqual([expect.objectContaining({ path: "auth.privateKeyPem" })]);
  });

  it("rejects an unknown environment", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ environment: "https://evil.example.com" }))
      .expect(400);
  });

  it("rejects an allow path that is not a valid route pattern", async () => {
    const res = await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ allow: [{ method: "GET", path: "/api/(unclosed" }] }))
      .expect(400);

    expect(res.body.details).toEqual([expect.objectContaining({ path: "allow.0.path" })]);
  });

  // Each optional group doubles the regex the proxy compiles per request (CPU amplification).
  it.each([
    ["3 optional groups", [{ method: "GET", path: "/x{/:a}{/:b}{/:c}" }], "allow.0.path"],
    ["an over-long path", [{ method: "GET", path: `/${"a".repeat(256)}` }], "allow.0.path"],
    [
      "65 entries",
      Array.from({ length: 65 }, (_, i) => ({ method: "GET", path: `/x/${i}` })),
      "allow",
    ],
  ])("rejects an allowlist with %s", async (_, allow, path) => {
    const res = await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ allow }))
      .expect(400);

    expect(res.body.details).toEqual([expect.objectContaining({ path })]);
  });

  // Small-order keys let anyone forge the host JWS without a private key.
  it.each([
    ["identity", IDENTITY_KEY],
    ["order-2", "7P_______________________________________38"],
    ["order-8, sign bit set", "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_IU"],
  ])("rejects a small-order host key (%s)", async (_name, hostPublicKey) => {
    const res = await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ hostPublicKey }))
      .expect(400);

    expect(res.body.details).toEqual([expect.objectContaining({ path: "hostPublicKey" })]);
    expect(storeArmed()).not.toHaveBeenCalled();
  });

  it("400, not 500, for a host key that decodes to fewer than 32 bytes", async () => {
    await request(app)
      .post("/arm")
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .send(armBody({ hostPublicKey: "AQ" }))
      .expect(400);
  });

  it("stores the armed record and returns its id", async () => {
    const id = await arm();

    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(storeArmed()).toHaveBeenCalledWith(id, armBody());
    expect(armed().get(id)?.auth).toEqual({ apiKey: "iron-secret" });
  });

  it("returns a unique id each call", async () => {
    expect(await arm()).not.toBe(await arm());
  });
});

describe("DELETE /arm/:id", () => {
  beforeEach(resetMocks);

  it("rejects a missing arm token", async () => {
    const id = await arm();

    await request(app).delete(`/arm/${id}`).expect(401);
    expect(deleteArmed()).not.toHaveBeenCalled();
  });

  it("404 for an id that is not a UUID, without a DynamoDB call", async () => {
    await request(app)
      .delete(`/arm/${"x".repeat(3000)}`)
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .expect(404);
    expect(deleteArmed()).not.toHaveBeenCalled();
  });

  it("204 for an unknown UUID: disarm is idempotent", async () => {
    await request(app)
      .delete(`/arm/${crypto.randomUUID()}`)
      .set("Authorization", `Bearer ${ARM_TOKEN}`)
      .expect(204);
  });

  it("disarms, so later proxy calls get 404", async () => {
    const id = await arm();
    const jws = await hostJws({ method: "GET", path: "/api/identifications/x" });

    await request(app).delete(`/arm/${id}`).set("Authorization", `Bearer ${ARM_TOKEN}`).expect(204);

    await request(app)
      .get(`/proxy/${id}/api/identifications/x`)
      .set("Authorization", `Bearer ${jws}`)
      .expect(404);
  });
});
