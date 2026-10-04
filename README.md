# @foomlabglobal/auth

Two helpers every Foom service uses to talk to the central IdP (Keycloak):

- `createTokenVerifier` — verify access tokens (ES256, pinned issuer + audience, JWKS fetched and cached).
- `clientCredentials` — get a service-to-service token, cached until 60 s before expiry.

Plain CommonJS, no build step. Works from both `require` and `import`. Node ≥ 18.

## Install

```json
"@foomlabglobal/auth": "github:foomlabglobal/auth#v1.0.0"
```

Public repo, so `npm ci` needs no credentials. The lockfile pins the exact commit.

## Verify incoming tokens

```js
const { createTokenVerifier } = require("@foomlabglobal/auth"); // or: import { ... } from

const verify = createTokenVerifier({
  issuers: [
    {
      issuer: process.env.AUTH_WORKFORCE_ISSUER,   // e.g. https://auth.example.com/realms/workforce
      audience: "rota",
      jwksUri: process.env.AUTH_WORKFORCE_JWKS_URI, // .../protocol/openid-connect/certs
    },
  ],
});

const { issuer, payload } = await verify(token); // throws if invalid
```

Only issuers in the list are trusted. The token's `iss` picks the key set, and the signature, `iss`, `aud`, `exp` and algorithm are all checked against that entry.

**Authorization is not this package's job.** Use `issuer` + `payload.sub` / `payload.email` to look up the user in your own database and take roles from there.

## Call another service

```js
const { clientCredentials } = require("@foomlabglobal/auth");

const getToken = clientCredentials({
  tokenUrl: process.env.AUTH_TOKEN_URL,
  clientId: process.env.AUTH_CLIENT_ID,
  clientSecret: process.env.AUTH_CLIENT_SECRET,
});

await axios.get(url, { headers: { Authorization: `Bearer ${await getToken()}` } });
```

## Rules for this repo

- Public on purpose: no secrets, hostnames or realm names in code. Everything comes from config.
- `main` is protected and needs review. Only maintainers create `v*` tags.

## Test

```sh
npm test
```
