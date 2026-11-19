import crypto from 'node:crypto';
import { vuln, award } from './config.js';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export const fail = (status, message) => { throw new HttpError(status, message); };

export function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  const status = err.status ?? err.statusCode ?? 500;
  if (vuln('L2-VERBOSE-ERRORS')) {
    award(res, 'L2-VERBOSE-ERRORS');
    return res.status(status).json({
      error: err.message,
      type: err.name,
      stack: err.stack?.split('\n').map((l) => l.trim()),
      runtime: { node: process.version, cwd: process.cwd(), database: 'sqlite :memory:', pid: process.pid },
    });
  }
  // Errors the code raised on purpose keep their status and message; anything else is hidden.
  if (!(err instanceof HttpError) && status >= 500) {
    const requestId = crypto.randomUUID();
    console.error(requestId, err);
    return res.status(500).json({ error: 'Internal error', requestId });
  }
  res.status(status).json({ error: err.expose === false ? 'Bad request' : err.message });
}
