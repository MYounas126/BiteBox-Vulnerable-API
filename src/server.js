import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { settings, configure, WEAKNESSES, vuln } from './config.js';
import { startInternal } from './internal.js';
import { buildApp } from './app.js';

export async function startLab(overrides = {}) {
  configure(overrides);
  const internal = await startInternal(settings.internalPort);
  settings.internalPort = internal.address().port;
  const server = buildApp().listen(settings.port, settings.host);
  await once(server, 'listening');
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    internalPort: settings.internalPort,
    close: () => { server.closeAllConnections(); server.close(); internal.close(); },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const lab = await startLab();
  const live = Object.keys(WEAKNESSES).filter(vuln);
  console.log(`Bitebox API lab, level ${settings.level}, ${settings.secure ? 'SECURE mode' : 'vulnerable mode'}`);
  console.log(`Listening on ${settings.host}:${settings.port}. ${live.length} weaknesses live.`);
  console.log(`Spec: ${lab.url}/api/v2/openapi.json`);
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { lab.close(); process.exit(0); });
}
