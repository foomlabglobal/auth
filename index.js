"use strict";

const { createRemoteJWKSet, decodeJwt, jwtVerify } = require("jose");

const ALGORITHMS = ["ES256"];
const REFRESH_MARGIN_MS = 60_000;

/**
 * Verifies access tokens from a fixed list of trusted issuers.
 *
 * issuers: [{ issuer, audience, jwksUri }]
 * Returns verify(token) -> { issuer, payload }; throws on any invalid token.
 */
function createTokenVerifier({ issuers }) {
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw new Error("createTokenVerifier: issuers must be a non-empty array");
  }

  const trusted = new Map(
    issuers.map(({ issuer, audience, jwksUri }) => {
      if (!issuer || !audience || !jwksUri) {
        throw new Error(
          "createTokenVerifier: each issuer needs issuer, audience and jwksUri"
        );
      }
      return [
        issuer,
        { audience, jwks: createRemoteJWKSet(new URL(jwksUri)) },
      ];
    })
  );

  return async function verify(token) {
    // The unverified `iss` only selects which key set to try; jwtVerify below
    // re-checks it against that same issuer, so a forged `iss` cannot pass
    // with another realm's key.
    const { iss } = decodeJwt(token);
    const entry = trusted.get(iss);
    if (!entry) {
      throw new Error("Untrusted token issuer");
    }

    const { payload } = await jwtVerify(token, entry.jwks, {
      algorithms: ALGORITHMS,
      issuer: iss,
      audience: entry.audience,
    });

    return { issuer: iss, payload };
  };
}

/**
 * OAuth2 client-credentials grant with an in-memory token cache.
 * Returns getToken() -> access token string.
 */
function clientCredentials({ tokenUrl, clientId, clientSecret }) {
  if (!tokenUrl || !clientId || !clientSecret) {
    throw new Error(
      "clientCredentials: tokenUrl, clientId and clientSecret are required"
    );
  }

  let cached = null;
  let pending = null;

  async function fetchToken() {
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization:
          "Basic " +
          Buffer.from(
            `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
          ).toString("base64"),
      },
      body: "grant_type=client_credentials",
    });

    if (!response.ok) {
      throw new Error(`Token request failed with HTTP ${response.status}`);
    }

    const body = await response.json();
    cached = {
      token: body.access_token,
      expiresAt: Date.now() + body.expires_in * 1000,
    };
    return cached.token;
  }

  return async function getToken() {
    if (cached && cached.expiresAt - REFRESH_MARGIN_MS > Date.now()) {
      return cached.token;
    }
    // Concurrent callers share one in-flight request.
    pending ??= fetchToken().finally(() => {
      pending = null;
    });
    return pending;
  };
}

module.exports = { createTokenVerifier, clientCredentials };
