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

const SETUP_ACTIONS = ["VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP"];
const INVITE_LIFESPAN_SECONDS = 3 * 24 * 60 * 60;

/**
 * Creates sign-in accounts through the Keycloak admin API, so apps can add
 * people without the admin console.
 *
 * adminUrl: Keycloak base URL reachable from the service (the public hostname
 *   usually blocks /admin).
 * clientId: the provisioner client, same id in every realm.
 * secrets: { [realmName]: clientSecret }
 * Returns provisionAccount({ realm, email, name, organization? })
 *   -> { realm, created, invited }. Errors carry `.status` when Keycloak
 *   answered with an HTTP error.
 */
function createAccountProvisioner({ adminUrl, clientId, secrets }) {
  if (!adminUrl || !clientId || !secrets) {
    throw new Error(
      "createAccountProvisioner: adminUrl, clientId and secrets are required"
    );
  }

  const tokenGetters = {};
  const tokenFor = (realm) => {
    if (!secrets[realm]) {
      throw new Error(`createAccountProvisioner: no secret for realm ${realm}`);
    }
    tokenGetters[realm] ??= clientCredentials({
      tokenUrl: `${adminUrl}/realms/${realm}/protocol/openid-connect/token`,
      clientId,
      clientSecret: secrets[realm],
    });
    return tokenGetters[realm]();
  };

  // 409 is fine everywhere we call it: the user/member already exists.
  async function adminFetch(realm, path, { method = "GET", body } = {}) {
    let response;
    try {
      response = await fetch(`${adminUrl}/admin/realms/${realm}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${await tokenFor(realm)}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new Error(`Keycloak ${method} ${path}: ${error.message}`);
    }
    if (!response.ok && response.status !== 409) {
      const error = new Error(
        `Keycloak ${method} ${path} failed with HTTP ${response.status}`
      );
      error.status = response.status;
      throw error;
    }
    return response;
  }

  async function findUser(realm, email) {
    const response = await adminFetch(
      realm,
      `/users?email=${encodeURIComponent(email)}&exact=true`
    );
    return (await response.json())[0] ?? null;
  }

  async function createUser(realm, { email, name }) {
    // Many people have a single name; last name stays empty then.
    const [firstName, ...rest] = name.trim().split(/\s+/);
    await adminFetch(realm, "/users", {
      method: "POST",
      body: {
        username: email,
        email,
        firstName,
        lastName: rest.join(" "),
        enabled: true,
        requiredActions: SETUP_ACTIONS,
      },
    });
    return findUser(realm, email);
  }

  async function ensureOrganization(realm, { name, alias }) {
    const find = async () => {
      const response = await adminFetch(
        realm,
        "/organizations?briefRepresentation=true&max=1000"
      );
      return (await response.json()).find((org) => org.alias === alias);
    };
    const existing = await find();
    if (existing) return existing;

    await adminFetch(realm, "/organizations", {
      method: "POST",
      body: { name, alias, enabled: true },
    });
    return find();
  }

  /**
   * Makes sure the person has an account in `realm` (and is a member of
   * `organization`, matched by alias, when given), and emails them the setup
   * link if they haven't finished setting up. Re-running is safe.
   */
  return async function provisionAccount({ realm, email, name, organization }) {
    let user = await findUser(realm, email);
    const created = !user;
    if (created) {
      user = await createUser(realm, { email, name });
    }

    if (organization) {
      const org = await ensureOrganization(realm, organization);
      await adminFetch(realm, `/organizations/${org.id}/members`, {
        method: "POST",
        body: user.id,
      });
    }

    // New accounts, and ones whose owner never finished the setup email.
    const invited = created || user.requiredActions?.length > 0;
    if (invited) {
      await adminFetch(
        realm,
        `/users/${user.id}/execute-actions-email?lifespan=${INVITE_LIFESPAN_SECONDS}`,
        { method: "PUT", body: SETUP_ACTIONS }
      );
    }

    return { realm, created, invited };
  };
}

module.exports = {
  createTokenVerifier,
  clientCredentials,
  createAccountProvisioner,
};
