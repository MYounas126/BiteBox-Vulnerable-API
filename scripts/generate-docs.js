// Writes docs/openapi.json and the Postman collection from the route registry.
import fs from 'node:fs';
import { configure } from '../src/config.js';
import { buildApp } from '../src/app.js';
import { openApi, postman } from '../src/spec.js';

configure({ level: 1, secure: false });
buildApp();
fs.writeFileSync('docs/openapi.json', `${JSON.stringify(openApi(), null, 2)}\n`);
fs.writeFileSync('postman/bitebox.postman_collection.json', `${JSON.stringify(postman(), null, 2)}\n`);
const ops = Object.values(openApi().paths).reduce((n, p) => n + Object.keys(p).length, 0);
console.log(`Wrote docs/openapi.json (${ops} operations) and postman/bitebox.postman_collection.json`);
