"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const { after, before, test } = require("node:test");
const { SignJWT, exportJWK, generateKeyPair } = require("jose");
const { clientCredentials, createTokenVerifier } = require("..");

const servers = [];
let realmA;
let realmB;
let verify;

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler).listen(0, "127.0.0.1", () => {
      servers.push(server);
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

async function makeRealm(name, alg = "ES256") {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwk = { ...(await exportJWK(publicKey)), kid: name, alg };
  const base = await listen((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  return { issuer: `${base}/realms/${name}`, jwksUri: `${base}/certs`, privateKey, alg, kid: name };
}

function sign(realm, { iss = realm.issuer, aud = "rota", exp = "5m", alg = realm.alg } = {}) {
  return new SignJWT({ sub: "user-1" })
    .setProtectedHeader({ alg, kid: realm.kid })
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(realm.privateKey);
}

before(async () => {
  realmA = await makeRealm("workforce");
  realmB = await makeRealm("partner");
  verify = createTokenVerifier({
    issuers: [
      { issuer: realmA.issuer, audience: "rota", jwksUri: realmA.jwksUri },
      { issuer: realmB.issuer, audience: "rota", jwksUri: realmB.jwksUri },
    ],
  });
});

after(() => servers.forEach((s) => s.close()));

test("accepts a valid token from each trusted issuer", async () => {
  const a = await verify(await sign(realmA));
  assert.equal(a.issuer, realmA.issuer);
  assert.equal(a.payload.sub, "user-1");
  const b = await verify(await sign(realmB));
  assert.equal(b.issuer, realmB.issuer);
});

test("rejects an unknown issuer", async () => {
  await assert.rejects(verify(await sign(realmA, { iss: "https://evil.example/realms/x" })));
});

test("rejects the wrong audience", async () => {
  await assert.rejects(verify(await sign(realmA, { aud: "backend-admin" })));
});

test("rejects an expired token", async () => {
  await assert.rejects(verify(await sign(realmA, { exp: Math.floor(Date.now() / 1000) - 10 })));
});

test("rejects a token signed by one realm claiming the other realm's issuer", async () => {
  await assert.rejects(verify(await sign(realmA, { iss: realmB.issuer })));
});

test("rejects a non-ES256 algorithm even with a trusted key set", async () => {
  const rsa = await makeRealm("rsa", "RS256");
  const v = createTokenVerifier({
    issuers: [{ issuer: rsa.issuer, audience: "rota", jwksUri: rsa.jwksUri }],
  });
  await assert.rejects(v(await sign(rsa)));
});

test("rejects garbage", async () => {
  await assert.rejects(verify("not-a-jwt"));
  await assert.rejects(verify("0123456789abcdef0123456789abcdef"));
});

test("clientCredentials caches the token and shares in-flight requests", async () => {
  let calls = 0;
  let auth;
  let body;
  const base = await listen((req, res) => {
    calls += 1;
    auth = req.headers.authorization;
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      body = data;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ access_token: `tok-${calls}`, expires_in: 300 }));
    });
  });
  const getToken = clientCredentials({ tokenUrl: `${base}/token`, clientId: "backend@foom", clientSecret: "s3cret" });

  const [t1, t2] = await Promise.all([getToken(), getToken()]);
  assert.equal(t1, "tok-1");
  assert.equal(t2, "tok-1");
  assert.equal(await getToken(), "tok-1");
  assert.equal(calls, 1);
  assert.equal(body, "grant_type=client_credentials");
  assert.equal(auth, "Basic " + Buffer.from("backend%40foom:s3cret").toString("base64"));
});

test("clientCredentials refetches when the token is near expiry", async () => {
  let calls = 0;
  const base = await listen((req, res) => {
    calls += 1;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ access_token: `tok-${calls}`, expires_in: 30 }));
  });
  const getToken = clientCredentials({ tokenUrl: `${base}/token`, clientId: "c", clientSecret: "s" });
  assert.equal(await getToken(), "tok-1");
  assert.equal(await getToken(), "tok-2");
});

test("clientCredentials surfaces HTTP errors", async () => {
  const base = await listen((req, res) => {
    res.statusCode = 401;
    res.end("{}");
  });
  const getToken = clientCredentials({ tokenUrl: `${base}/token`, clientId: "c", clientSecret: "bad" });
  await assert.rejects(getToken(), /HTTP 401/);
});
