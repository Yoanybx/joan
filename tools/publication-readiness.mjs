#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REQUIRED_VARIABLES = [
  "JOAN_RELEASE_APPROVAL_ID",
  "JOAN_RELEASE_APPROVED_COMMIT",
  "JOAN_RELEASE_APPROVED_TAG",
];
const READINESS_BOOLEAN_PATHS = [
  ["official_repository", "configured"],
  ["legal", "assignment_instrument_recorded"],
  ["legal", "asset_inventory_approved"],
  ["legal", "license_decision_approved"],
  ["legal", "contributor_terms_approved"],
  ["legal", "trademark_clearance_recorded"],
  ["security", "private_vulnerability_reporting_enabled"],
  ["security", "recovery_procedure_tested"],
  ["release", "public_release_approved"],
  ["release", "environment_protection_configured"],
  ["release", "tag_rules_configured"],
  ["release", "codeowners_configured"],
  ["release", "signing_identity_bound"],
  ["release", "hosted_ci_passed"],
  ["release", "independent_rerun_verified"],
];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function object(value, label) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  assert(JSON.stringify(actual) === JSON.stringify(wanted), `${label} fields do not match the v0 contract`);
}

function boolean(value, label) {
  assert(typeof value === "boolean", `${label} must be a boolean`);
}

function at(value, path) {
  return path.reduce((current, key) => current[key], value);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function validatePublicationReadiness({ readiness, project, origin, mode, env, codeownersExists }) {
  assert(mode === "source" || mode === "release", "mode must be source or release");
  exactKeys(readiness, [
    "schema", "status", "project", "original_creator", "corporate_owner", "official_repository", "legal",
    "security", "release", "authorization", "publication_effect",
  ], "publication readiness");
  exactKeys(readiness.official_repository, ["configured", "owner", "name"], "official_repository");
  exactKeys(readiness.legal, [
    "assignment_instrument_recorded", "asset_inventory_approved", "license_decision_approved",
    "license_profile", "contributor_terms_approved", "trademark_clearance_recorded",
  ], "legal");
  exactKeys(readiness.security, ["private_vulnerability_reporting_enabled", "recovery_procedure_tested"], "security");
  exactKeys(readiness.release, [
    "public_release_approved", "protected_environment", "environment_protection_configured",
    "tag_rules_configured", "codeowners_configured", "signing_identity_bound", "hosted_ci_passed",
    "independent_rerun_verified",
  ], "release");
  exactKeys(readiness.authorization, ["source", "required_variables"], "authorization");

  assert(readiness.schema === "joan.publication-readiness.v0", "publication readiness schema mismatch");
  assert(["blocked", "ready"].includes(readiness.status), "publication readiness status is invalid");
  assert(readiness.project === "JOAN Language and JOAN Network", "project identity mismatch");
  assert(readiness.original_creator === "Joan Alberto Barrios Cruz", "original creator mismatch");
  assert(readiness.corporate_owner === "LED ACTION LLC", "corporate owner mismatch");
  assert(readiness.publication_effect === "not-executed", "repository state cannot assert a publication effect");
  assert(readiness.release.protected_environment === "release", "protected release environment name drift");
  assert(readiness.authorization.source === "protected-environment-variables", "authorization source drift");
  assert(JSON.stringify(readiness.authorization.required_variables) === JSON.stringify(REQUIRED_VARIABLES), "required release variables drift");
  assert(typeof readiness.legal.license_profile === "string" && readiness.legal.license_profile.length > 0, "license profile is missing");

  for (const path of READINESS_BOOLEAN_PATHS) boolean(at(readiness, path), path.join("."));
  const configured = readiness.official_repository.configured;
  if (configured) {
    assert(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u.test(readiness.official_repository.owner ?? ""), "official repository owner is invalid");
    assert(/^[A-Za-z0-9._-]{1,100}$/u.test(readiness.official_repository.name ?? ""), "official repository name is invalid");
  } else {
    assert(readiness.official_repository.owner === null && readiness.official_repository.name === null, "unconfigured repository must not name an owner or repository");
  }
  assert(readiness.release.codeowners_configured === codeownersExists, "CODEOWNERS file/state mismatch");
  assert(readiness.legal.license_profile === project.license_profile, "project/readiness license profile mismatch");
  assert(readiness.legal.assignment_instrument_recorded === project.assignment_instrument_recorded, "project/readiness assignment state mismatch");
  assert(readiness.legal.assignment_instrument_recorded === origin.assignment_instrument_recorded, "origin/readiness assignment state mismatch");
  assert(configured === project.remote_configured && configured === origin.remote_configured, "repository configuration state mismatch");
  assert(readiness.release.public_release_approved === project.public_release, "project/readiness public release state mismatch");
  assert(readiness.release.public_release_approved === origin.public_release, "origin/readiness public release state mismatch");
  assert(readiness.release.signing_identity_bound === origin.signing_identity_bound, "origin/readiness signing state mismatch");

  const complete = READINESS_BOOLEAN_PATHS.every((path) => at(readiness, path) === true);
  assert(readiness.status === (complete ? "ready" : "blocked"), "readiness status does not match required controls");

  if (mode === "release") {
    assert(complete, "public release is blocked by incomplete readiness controls");
    assert(env.GITHUB_REF_TYPE === "tag", "release authorization requires a GitHub tag ref");
    assert(`${readiness.official_repository.owner}/${readiness.official_repository.name}` === env.GITHUB_REPOSITORY, "GitHub repository does not match the approved official repository");
    assert(/^[0-9a-f]{40}$/u.test(env.JOAN_RELEASE_APPROVED_COMMIT ?? ""), "approved commit metadata is missing or invalid");
    assert(env.JOAN_RELEASE_APPROVED_COMMIT === env.GITHUB_SHA, "approved commit does not match checked-out source");
    assert(/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?$/u.test(env.JOAN_RELEASE_APPROVED_TAG ?? ""), "approved tag metadata is missing or invalid");
    assert(env.JOAN_RELEASE_APPROVED_TAG === env.GITHUB_REF_NAME, "approved tag does not match the workflow tag");
    assert(/^[A-Za-z0-9._:-]{8,128}$/u.test(env.JOAN_RELEASE_APPROVAL_ID ?? ""), "release approval identity is missing or invalid");
  }
  return { mode, status: readiness.status, complete, publication_effect: "not-executed" };
}

export function loadRepositoryState(root = ROOT) {
  return {
    readiness: readJson(resolve(root, ".joan/publication-readiness.json")),
    project: readJson(resolve(root, ".joan/project.json")),
    origin: readJson(resolve(root, ".joan/origin.json")),
    codeownersExists: existsSync(resolve(root, ".github/CODEOWNERS")),
  };
}

function main() {
  const mode = process.argv[2] ?? "source";
  const result = validatePublicationReadiness({ ...loadRepositoryState(), mode, env: process.env });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`publication readiness rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
