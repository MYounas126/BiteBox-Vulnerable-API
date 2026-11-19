// Builds the OpenAPI document and the Postman collection from the route registry.
import { routes } from './registry.js';

const VERSION = '2.4.1';
const documented = () => routes.filter((r) => r.documented);
const toOpenApiPath = (r) => `${r.base}${r.path === '/' ? '' : r.path}`.replace(/:(\w+)/g, '{$1}');

export function openApi() {
  const paths = {};
  for (const r of documented()) {
    const p = toOpenApiPath(r);
    const params = [...p.matchAll(/\{(\w+)\}/g)].map(([, name]) => ({
      name, in: 'path', required: true, schema: { type: 'integer' },
    }));
    for (const [name, example] of Object.entries(r.query ?? {})) {
      params.push({ name, in: 'query', required: false, schema: { type: 'string' }, example });
    }
    const op = { tags: [r.tag], summary: r.summary, parameters: params, responses: { 200: { description: 'OK' } } };
    if (r.auth !== 'none') {
      op.security = [{ bearerAuth: [] }];
      op.responses[401] = { description: 'Not logged in' };
      if (Array.isArray(r.auth)) op.description = `Roles: ${r.auth.join(', ')}`;
    }
    if (r.body) op.requestBody = { required: true, content: { 'application/json': { example: r.body } } };
    (paths[p] ??= {})[r.method] = op;
  }
  return {
    openapi: '3.0.3',
    info: { title: 'Bitebox API', version: VERSION, description: 'Food delivery marketplace API. Training lab: runs on 127.0.0.1 only.' },
    servers: [{ url: 'http://127.0.0.1:8000' }],
    components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
    paths,
  };
}

const SAVE_TOKENS = [
  'const b = pm.response.json();',
  'if (b.accessToken) pm.collectionVariables.set("accessToken", b.accessToken);',
  'if (b.refreshToken) pm.collectionVariables.set("refreshToken", b.refreshToken);',
];

export function postman() {
  const folders = new Map();
  for (const r of documented()) {
    const segments = `${r.base}${r.path === '/' ? '' : r.path}`.split('/').filter(Boolean);
    const item = {
      name: r.summary,
      request: {
        method: r.method.toUpperCase(),
        header: r.body ? [{ key: 'Content-Type', value: 'application/json' }] : [],
        url: {
          raw: `{{baseUrl}}/${segments.join('/')}`,
          host: ['{{baseUrl}}'],
          path: segments,
          variable: segments.filter((s) => s.startsWith(':')).map((s) => ({ key: s.slice(1), value: '1' })),
          query: Object.entries(r.query ?? {}).map(([key, value]) => ({ key, value, disabled: true })),
        },
        auth: r.auth === 'none' ? { type: 'noauth' } : { type: 'bearer', bearer: [{ key: 'token', value: '{{accessToken}}', type: 'string' }] },
      },
    };
    if (r.body) item.request.body = { mode: 'raw', raw: JSON.stringify(r.body, null, 2), options: { raw: { language: 'json' } } };
    if (['/register', '/login', '/otp/verify', '/refresh'].includes(r.path) && r.tag === 'Auth') {
      item.event = [{ listen: 'test', script: { type: 'text/javascript', exec: SAVE_TOKENS } }];
    }
    if (!folders.has(r.tag)) folders.set(r.tag, []);
    folders.get(r.tag).push(item);
  }
  return {
    info: {
      name: `Bitebox API ${VERSION}`,
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
      description: 'Run Register or Log in first; the token is saved to the collection automatically.',
    },
    variable: [
      { key: 'baseUrl', value: 'http://127.0.0.1:8000' },
      { key: 'accessToken', value: '' },
      { key: 'refreshToken', value: '' },
    ],
    item: [...folders].map(([name, item]) => ({ name, item })),
  };
}
