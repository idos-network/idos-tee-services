import { afterEach, describe, expect, it, vi } from "vitest";

describe("boot guard", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  const load = (skip: string, baseUrl: string) => {
    vi.stubEnv("SKIP_AUDIENCE_VERIFICATION", skip);
    vi.stubEnv("BASE_URL", baseUrl);
    vi.resetModules();
    return import("../env.ts");
  };

  it.each([
    "https://enclave.tee.idos.network",
    "https://enclave.tee.idos.network/",
    "https://ENCLAVE.tee.idos.network:443",
    "enclave.tee.idos.network",
  ])("refuses to boot with SKIP_AUDIENCE_VERIFICATION on %s", async (baseUrl) => {
    await expect(load("true", baseUrl)).rejects.toThrow(/not allowed/);
  });

  it("boots in production with audience verification", async () => {
    await expect(load("false", "https://enclave.tee.idos.network")).resolves.toBeDefined();
  });

  it("allows skipping outside production", async () => {
    const env = await load("true", "https://enclave.staging.sandbox.fractal.id");
    expect(env.SKIP_AUDIENCE_VERIFICATION).toBe(true);
  });
});
