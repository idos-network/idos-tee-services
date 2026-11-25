import { parse, pathToRegexp, type Token } from "path-to-regexp";
import { z } from "zod";
import { ENVIRONMENTS, vendors } from "../providers/vendors/index.ts";
import { compiles } from "./compiles.ts";

export const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

// Small-order Ed25519 points (libsodium's ge25519_has_small_order list): with such a key
// [S]B = R + [k]A degenerates, so a JWS for any payload can be forged without a private key.
// Compared ignoring the x sign bit, which also covers the non-canonical encodings of y.
const SMALL_ORDER_POINTS = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/** True for a base64url Ed25519 `x` that is a small-order point, for which anyone can forge signatures. */
export function isSmallOrderEd25519(x: string): boolean {
  const bytes = Buffer.from(x, "base64url");
  // Zod still runs this refine after .length(43) fails, so a short key must not throw.
  if (bytes.length !== 32) return false;
  bytes.writeUInt8(bytes.readUInt8(31) & 0x7f, 31);
  return SMALL_ORDER_POINTS.includes(bytes.toString("hex"));
}

// path-to-regexp 8 expands each optional `{…}` group into 2^n regex alternatives, and the proxy
// compiles every entry on each request: unbounded, one armed record burns seconds of event-loop CPU.
export const MAX_ALLOW_ENTRIES = 64;
export const MAX_ALLOW_PATH_LENGTH = 256;
export const MAX_OPTIONAL_GROUPS = 2;

const optionalGroups = (tokens: Token[]): number =>
  tokens.reduce((n, t) => (t.type === "group" ? n + 1 + optionalGroups(t.tokens) : n), 0);

/** Cheap (linear parse, no regex expansion) check that a route pattern stays within the cost bounds. */
export function isBoundedPattern(path: string): boolean {
  return (
    path.length <= MAX_ALLOW_PATH_LENGTH &&
    compiles(() => {
      if (optionalGroups(parse(path).tokens) > MAX_OPTIONAL_GROUPS)
        throw new Error("too many groups");
    })
  );
}

const CommonArmSchema = z.object({
  // base64url-encoded 32-byte Ed25519 public key (JWK `x`)
  hostPublicKey: z
    .base64url()
    .length(43)
    .refine((x) => !isSmallOrderEd25519(x), { message: "Not a usable Ed25519 public key" }),
  // Picks the vendor origin from its adapter; the host never supplies a URL.
  environment: z.enum(ENVIRONMENTS),
  allow: z
    .array(
      z.object({
        method: z.enum(ALLOWED_METHODS),
        // Express 5 route syntax (path-to-regexp), e.g. /api/identifications/:id
        path: z
          .string()
          .startsWith("/")
          // bounds first, so pathToRegexp never expands an oversized pattern
          .refine((path) => isBoundedPattern(path) && compiles(() => pathToRegexp(path)), {
            message: `Not a valid route pattern (at most ${MAX_ALLOW_PATH_LENGTH} chars and ${MAX_OPTIONAL_GROUPS} optional groups)`,
          }),
      }),
    )
    .min(1)
    .max(MAX_ALLOW_ENTRIES),
});

// One variant per vendor: `api` picks the adapter, `auth` is whatever that adapter validates.
export const ArmRequestSchema = z.discriminatedUnion("api", [
  CommonArmSchema.extend({ api: z.literal("iron"), auth: vendors.iron.auth }),
  CommonArmSchema.extend({ api: z.literal("moonpay"), auth: vendors.moonpay.auth }),
  CommonArmSchema.extend({ api: z.literal("persona"), auth: vendors.persona.auth }),
  CommonArmSchema.extend({ api: z.literal("sumsub"), auth: vendors.sumsub.auth }),
  CommonArmSchema.extend({ api: z.literal("kalshi"), auth: vendors.kalshi.auth }),
  CommonArmSchema.extend({ api: z.literal("mock"), auth: vendors.mock.auth }),
]);

export type ArmRequest = z.infer<typeof ArmRequestSchema>;

// Armed ids are server-generated randomUUID()s; checking the shape answers 404 without a
// DynamoDB call, and keeps over-long ids from becoming a DynamoDB key error (500).
export const isArmedId = (id: string) => z.uuid().safeParse(id).success;

export const AttestationQuerySchema = z.object({ nonce: z.base64url().max(86).optional() });
