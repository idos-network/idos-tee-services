import { AsyncLocalStorage } from "node:async_hooks";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { NextFunction, Request, Response } from "express";
import type { Logger } from "pino";
import pino from "pino";
import { pinoHttp } from "pino-http";
import { getRequestId } from "./request-context.ts";

const loggerStorage = new AsyncLocalStorage<Logger>();

// Fallback logger for places outside of HTTP requests (e.g. startup, cron jobs)
const fallbackLogger = pino({
  formatters: { level: (label) => ({ level: label }) },
});

export const getLogger = (): Logger => {
  return loggerStorage.getStore() ?? fallbackLogger;
};

const sensitiveHeaders = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-id-token",
  "x-csrf-token",
  "x-xsrf-token",
  "x-signature",
  "x-hub-signature",
  "x-hub-signature-256",
  "x-amz-security-token",
];

const sensitiveHeaderPaths = sensitiveHeaders.flatMap((header) => [
  `req.headers['${header}']`,
  `res.headers['${header}']`,
  `headers['${header}']`,
]);

// Full request headers only help when a request failed, so only those get them.
function withFailedRequestHeaders(req: IncomingMessage, res: ServerResponse, val: object) {
  if (res.statusCode < 400) return val;
  const {
    "content-type": contentType,
    "content-length": contentLength,
    "accept-encoding": acceptEncoding,
  } = req.headers;
  return { ...val, reqHeaders: { contentType, contentLength, acceptEncoding } };
}

const logger = pinoHttp({
  enabled: process.env.NODE_ENV !== "test",
  formatters: {
    level: (label) => ({ level: label }),
  },
  genReqId: () => getRequestId() ?? "-",
  // Every line used to carry all request and response headers (~2 kB, mostly static helmet
  // headers), which outran log shipping under load. Dashboards read only req.url/method and res.statusCode.
  serializers: {
    req: (req) => ({
      id: req.id,
      method: req.method,
      url: req.url,
      ip: req.headers["x-real-ip"],
      userAgent: req.headers["user-agent"],
    }),
    res: (res) => ({ statusCode: res.statusCode }),
  },
  customSuccessObject: withFailedRequestHeaders,
  customErrorObject: (req, res, _error, val) => withFailedRequestHeaders(req, res, val),
  redact: {
    paths: sensitiveHeaderPaths,
    censor: "[Redacted]",
  },
  autoLogging: {
    ignore: (req: Request) => ["/", "/metrics", "/health"].includes(req.url ?? ""),
  },
});

export function loggerMiddleware(req: Request, res: Response, next: NextFunction) {
  logger(req, res, () => {
    loggerStorage.run(req.log, next);
  });
}

/**
 * Builds a service's writeLog: counts the event and logs it with the request logger.
 * The counter comes from the service so it lands in the registry its /metrics exposes.
 */
export function createWriteLog<Action extends string>(counter: {
  inc(labels: { action: Action }): void;
}) {
  return (eventType: Action, data: Record<string, unknown> = {}) => {
    counter.inc({ action: eventType });

    getLogger().info({
      eventType,
      ...data,
    });
  };
}
