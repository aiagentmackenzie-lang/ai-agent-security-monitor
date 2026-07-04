import { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';

/**
 * HTTP error with an explicit status code. Throw this from route handlers
 * instead of bare objects so the Fastify error handler can produce a clean,
 * typed response.
 */
export class HttpError extends Error {
  statusCode: number;
  details?: unknown;

  constructor(statusCode: number, message: string, details?: unknown) {
    super(message);
    this.name = 'HttpError';
    this.statusCode = statusCode;
    this.details = details;
  }

  static notFound(message: string): HttpError {
    return new HttpError(404, message);
  }

  static badRequest(message: string, details?: unknown): HttpError {
    return new HttpError(400, message, details);
  }

  static conflict(message: string): HttpError {
    return new HttpError(409, message);
  }

  static unauthorized(message: string): HttpError {
    return new HttpError(401, message);
  }
}

/**
 * Central Fastify error handler.
 *
 * - ZodError      → 400 with per-field validation details
 * - HttpError     → its explicit status code + details
 * - everything else → 500 (logged, message not leaked in production)
 */
export function errorHandler(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply
): void {
  if (error instanceof ZodError) {
    reply.code(400).send({
      error: 'Validation failed',
      details: error.issues.map(i => ({
        path: i.path.join('.'),
        message: i.message,
        code: i.code,
      })),
    });
    return;
  }

  if (error instanceof HttpError) {
    const body: Record<string, unknown> = { error: error.message };
    if (error.details !== undefined) body.details = error.details;
    reply.code(error.statusCode).send(body);
    return;
  }

  // Unknown error — log and hide internals
  request.log.error({ err: error }, 'Unhandled error');
  const isProd = process.env.NODE_ENV === 'production';
  reply.code(500).send({
    error: 'Internal server error',
    ...(isProd ? {} : { message: error.message }),
  });
}