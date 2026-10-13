import assert from "node:assert/strict";
import { test } from "node:test";
import {
  clientCredentials,
  createAccountProvisioner,
  createTokenVerifier,
} from "../index.js";

test("named exports are importable from ESM", () => {
  assert.equal(typeof createTokenVerifier, "function");
  assert.equal(typeof clientCredentials, "function");
  assert.equal(typeof createAccountProvisioner, "function");
});
