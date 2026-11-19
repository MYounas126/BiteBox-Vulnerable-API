# Bitebox, a deliberately vulnerable API

Bitebox is a fictional food delivery marketplace API, built for teaching API security testing. It has three roles, 41 documented REST operations, a GraphQL endpoint, and sixteen planted weaknesses mapped to the OWASP API Security Top 10.

All of the data is fake. All of the weaknesses are deliberate.

> **Warning**
> This application is insecure on purpose. Do not deploy it, do not put it on a network, and do not reuse any of its code. Every port is published on 127.0.0.1 only, and the compose file is written that way deliberately. Leave it that way.

## Why it exists

Most API security training is either a slide deck with no target, or a target with no structure. Bitebox is built around a teaching order. You raise the level one at a time, and each level switches on only the weaknesses for that chapter, so a learner is never hunting sixteen things at once.

It is also a real application rather than a set of broken endpoints. Orders, coupons, merchants, couriers, and webhooks all behave the way you would expect, which is what makes the logic flaws worth finding.

## Quick start

Requires Docker. Docker Desktop or Colima on Apple Silicon both work.

```bash
LAB_LEVEL=1 docker compose up -d --build
curl http://127.0.0.1:8000/api/v2/openapi.json | head
docker compose logs api
docker compose down
```

Restarting the lab resets all of its data.

| Service | Address |
|---|---|
| API | http://127.0.0.1:8000 |
| OpenAPI spec | http://127.0.0.1:8000/api/v2/openapi.json |
| GraphQL | http://127.0.0.1:8000/graphql |
| Listener log | http://127.0.0.1:8081/_log |

Set `API_PORT` if port 8000 is taken. The API deliberately sits on 8000 so that Burp can keep its default 8080.

## Levels

Set `LAB_LEVEL` to the chapter you are working on. Each level enables only its own weaknesses.

| Level | Chapter | OWASP API Top 10 | Weaknesses |
|---|---|---|---|
| 1 | Lab setup | None, everything is secure | 0 |
| 2 | Recon and inventory | API8, API9 | 4 |
| 3 | Authentication and tokens | API2 | 2 |
| 4 | Authorisation of objects, properties, and functions | API1, API3, API5 | 3 |
| 5 | Business logic, abuse, and SSRF | API4, API6, API7, API10 | 4 |
| 6 | GraphQL | All of the above, plus GraphQL | 3 |

`SECURE=true` switches every weakness off at any level, at any time. Use it to compare behaviour once you have finished hunting, not before.

## Flags

Each weakness you reach returns a flag in the `X-Lab-Flag` response header.

Flags are derived from `FLAG_SEED`, which defaults to `local-practice`. A trainer running a cohort should set their own seed, then check submissions against it:

```bash
FLAG_SEED=your-cohort-seed node checker/check.js --file submission.txt
```

**A flag on its own proves nothing.** Anyone holding the source can compute every flag without solving anything. Flags are a convenience for cross-checking, not evidence. Mark the request and the response.

## Accounts and the listener

Register your own accounts with `POST /api/v2/auth/register`, using an `accountType` of `customer` or `merchant`. A merchant account comes with its own restaurant.

Login codes and webhook deliveries go to the listener container rather than anywhere real, so read them at http://127.0.0.1:8081/_log.

The listener can also be told what to answer, which you need when it stands in for a partner service:

```bash
curl -X POST http://127.0.0.1:8081/_respond \
  -H 'content-type: application/json' \
  -d '{"path":"/courier","status":200,"body":{"fee":3,"etaMinutes":20}}'
```

## Postman

Import `postman/bitebox.postman_collection.json`. Run Register or Log in first and the collection stores your token for every other request. To send that traffic through Burp, point Postman's proxy at 127.0.0.1:8080.

## Fixing the code

The other half of the exercise is closing the holes rather than only finding them. Needs Node 22.13 or later.

```bash
npm install
npm test
```

`npm test` runs the regression suite against secure mode, plus a check that the lab never opens a connection outside itself. A fix that breaks that check is the wrong fix.

`npm start` runs the API outside Docker, bound to 127.0.0.1. `npm run gen` rebuilds the OpenAPI spec and the Postman collection after you change routes.

## Layout

```
src/        the application
listener/   the stand-in partner service and callback sink
tests/      regression suite, runs against secure mode
checker/    flag verification for trainers
postman/    importable collection
docs/       generated OpenAPI spec
scripts/    regenerates the spec and the collection
```

## What is not in this repository

The `trainer/` directory is the answer key. It proves every weakness is reachable and names each one, so it is held back deliberately while this lab is in use for assessment. Without it the lab is complete and every weakness is still reachable.

If you are running your own cohort and want the key, the test file it contains is straightforward to reconstruct from `src/config.js`, which lists every weakness id.

## Safety

- Run it on your own machine only.
- Test only with accounts you registered yourself.
- Callbacks go to the listener container and nowhere else. The API enforces this itself, in every mode.
- The techniques this lab teaches must never be used against a system you do not have written permission to test.

## Credits

Built by [MYounas126](https://github.com/MYounas126) for the Security Testing Boot Camp.
