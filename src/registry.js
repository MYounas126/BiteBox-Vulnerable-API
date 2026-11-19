// Every route is registered with a little metadata, so the OpenAPI spec and the
// Postman collection are generated from the code and cannot drift from it.
// Routes marked documented: false are left out of both, on purpose.
export const routes = [];

export function resetRegistry() {
  routes.length = 0;
}

export function registry(router, base, tag) {
  const add = (method) => (path, meta, ...handlers) => {
    routes.push({ method, base, path, tag, documented: true, auth: 'user', ...meta });
    router[method](path, ...handlers);
  };
  return { get: add('get'), post: add('post'), put: add('put'), patch: add('patch'), delete: add('delete') };
}
