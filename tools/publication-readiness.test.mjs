#!/usr/bin/env node

import assert from "node:assert/strict";
import { loadRepositoryState, validatePublicationReadiness } from "./publication-readiness.mjs";

function clone(value) {
  return structuredClone(value);
}

function rejects(state, mode, env, pattern) {
  assert.throws(
    () => validatePublicationReadiness({ ...state, mode, env }),
    pattern,
  );
}

const baseline = loadRepositoryState();
const source = validatePublicationReadiness({ ...baseline, mode: "source", env: {} });
assert.deepEqual(source, {
  mode: "source",
  status: "blocked",
  complete: false,
  publication_effect: "not-executed",
});
rejects(baseline, "release", {}, /incomplete readiness controls/u);

const unknownField = clone(baseline);
unknownField.readiness.unexpected = true;
rejects(unknownField, "source", {}, /fields do not match/u);

const namedButUnconfigured = clone(baseline);
namedButUnconfigured.readiness.official_repository.configured = false;
namedButUnconfigured.readiness.official_repository.owner = "led-action";
namedButUnconfigured.readiness.official_repository.name = "joan";
rejects(namedButUnconfigured, "source", {}, /must not name/u);

const ready = clone(baseline);
ready.readiness.status = "ready";
ready.readiness.official_repository = { configured: true, owner: "led-action", name: "joan" };
for (const section of [ready.readiness.legal, ready.readiness.security, ready.readiness.release]) {
  for (const [key, value] of Object.entries(section)) {
    if (typeof value === "boolean") section[key] = true;
  }
}
ready.readiness.legal.license_profile = "owner-and-counsel-approved-profile";
ready.project.license_profile = "owner-and-counsel-approved-profile";
ready.project.assignment_instrument_recorded = true;
ready.project.remote_configured = true;
ready.project.public_release = true;
ready.origin.assignment_instrument_recorded = true;
ready.origin.remote_configured = true;
ready.origin.public_release = true;
ready.origin.signing_identity_bound = true;
ready.codeownersExists = true;

const releaseEnv = {
  GITHUB_REF_TYPE: "tag",
  GITHUB_REPOSITORY: "led-action/joan",
  GITHUB_SHA: "a".repeat(40),
  GITHUB_REF_NAME: "v1.0.0",
  JOAN_RELEASE_APPROVAL_ID: "LED-REL-0001",
  JOAN_RELEASE_APPROVED_COMMIT: "a".repeat(40),
  JOAN_RELEASE_APPROVED_TAG: "v1.0.0",
};
assert.equal(validatePublicationReadiness({ ...ready, mode: "release", env: releaseEnv }).complete, true);

const wrongCommit = { ...releaseEnv, JOAN_RELEASE_APPROVED_COMMIT: "b".repeat(40) };
rejects(ready, "release", wrongCommit, /approved commit does not match/u);
const wrongRepository = { ...releaseEnv, GITHUB_REPOSITORY: "fork/joan" };
rejects(ready, "release", wrongRepository, /does not match the approved official repository/u);

process.stdout.write("publication readiness controls: 7/7 passed\n");
