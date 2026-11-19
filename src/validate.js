import { fail } from './errors.js';

export const body = (req) => (req.body && typeof req.body === 'object' ? req.body : {});

export function str(v, name, { min = 1, max = 200, optional = false, pattern } = {}) {
  if (v === undefined || v === null) {
    if (optional) return undefined;
    fail(400, `${name} is required`);
  }
  if (typeof v !== 'string') fail(400, `${name} must be a string`);
  const s = v.trim();
  if (s.length < min || s.length > max) fail(400, `${name} must be ${min} to ${max} characters`);
  if (pattern && !pattern.test(s)) fail(400, `${name} has an invalid format`);
  return s;
}

export function int(v, name, { min = 1, max = Number.MAX_SAFE_INTEGER, optional = false } = {}) {
  if (v === undefined || v === null || v === '') {
    if (optional) return undefined;
    fail(400, `${name} is required`);
  }
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) fail(400, `${name} must be a whole number from ${min} to ${max}`);
  return n;
}

export function money(v, name, { min = 0, max = 1000 } = {}) {
  const n = Number(v);
  if (typeof v !== 'number' || !Number.isFinite(n) || n < min || n > max) fail(400, `${name} must be a number from ${min} to ${max}`);
  return Math.round(n * 100) / 100;
}

export const id = (req, name = 'id') => int(req.params[name], name);

export const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const PHONE = /^\+?[0-9 ]{7,16}$/;
