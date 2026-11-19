// biome-ignore-all lint/style/noNonNullAssertion: This is ok
export const GROUP_NAME = "proxy-service";
export const DYNAMODB_ARMED_TABLE = process.env.DYNAMODB_ARMED_TABLE!;
// base64, 96 bytes: master key the armed-record AES key is derived from, see scripts/run.ash
export const FLE_MASTER_KEY = process.env.FLE_MASTER_KEY!;
// Bearer tokens allowed to call POST /arm (comma separated in config.env).
export const ARM_TOKENS = (process.env.ARM_TOKENS ?? "")
  .split(",")
  .map((token) => token.trim())
  .filter(Boolean);
// How long a host JWS stays valid after its iat.
export const HOST_JWS_MAX_AGE = "5 minutes";
// The enclave has no NTP, so its clock drifts from the host's; iat is whole seconds.
export const HOST_JWS_CLOCK_TOLERANCE = "30 seconds";
export const UPSTREAM_TIMEOUT_MS = 30_000;
