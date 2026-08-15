#!/usr/bin/env node

import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, normalizeSbom, validateSbomDocument } from "./sbom-evidence.mjs";

const TIMESTAMP = "2026-08-15T07:01:51.000000000Z";

function fixture() {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: TIMESTAMP,
      tools: [{ vendor: "CycloneDX", name: "cargo-cyclonedx", version: "0.5.9" }],
      component: {
        type: "application",
        "bom-ref": "path+file:///Volumes/private/repo/crates/joan-node#0.1.0-alpha.1",
        name: "joan",
        version: "0.1.0-alpha.1",
        purl: "pkg:cargo/joan-node@0.1.0-alpha.1?download_url=file://.#src/main.rs",
        components: [
          {
            type: "application",
            "bom-ref":
              "path+file:///Volumes/private/repo/crates/joan-node#0.1.0-alpha.1 bin-target-0",
            name: "joan",
            version: "0.1.0-alpha.1",
            purl: "pkg:cargo/joan-node@0.1.0-alpha.1?download_url=file://.#src/main.rs",
          },
        ],
      },
    },
    components: [
      {
        type: "library",
        "bom-ref": "pkg:cargo/serde@1.0.229",
        name: "serde",
        version: "1.0.229",
        purl: "pkg:cargo/serde@1.0.229",
      },
    ],
    dependencies: [
      {
        ref: "path+file:///Volumes/private/repo/crates/joan-node#0.1.0-alpha.1",
        dependsOn: ["pkg:cargo/serde@1.0.229"],
      },
      { ref: "pkg:cargo/serde@1.0.229", dependsOn: [] },
    ],
  };
}

test("normalization removes checkout paths and preserves dependency edges", () => {
  const normalized = normalizeSbom(fixture());
  const encoded = canonicalJson(normalized);
  assert.doesNotMatch(encoded, /\/Volumes\/|file:\/\//u);
  assert.match(encoded, /pkg:cargo\/joan-node@0\.1\.0-alpha\.1/u);
  assert.match(encoded, /urn:joan:cargo-target:joan-node:joan/u);
  assert.deepEqual(validateSbomDocument(normalized, TIMESTAMP), {
    componentCount: 2,
    dependencyCount: 2,
  });
});

test("random serial numbers are rejected", () => {
  const normalized = normalizeSbom(fixture());
  normalized.serialNumber = "urn:uuid:00112233-4455-6677-8899-aabbccddeeff";
  assert.throws(() => validateSbomDocument(normalized, TIMESTAMP), /omit serialNumber/u);
});

test("timestamp drift is rejected", () => {
  const normalized = normalizeSbom(fixture());
  normalized.metadata.timestamp = "2026-08-15T07:01:52.000000000Z";
  assert.throws(() => validateSbomDocument(normalized, TIMESTAMP), /source-derived/u);
});

test("missing components and dangling dependency edges are rejected", () => {
  const missing = normalizeSbom(fixture());
  missing.components = [];
  assert.throws(() => validateSbomDocument(missing, TIMESTAMP), /unknown component/u);

  const dangling = normalizeSbom(fixture());
  dangling.dependencies[0].dependsOn.push("pkg:cargo/missing@1.0.0");
  assert.throws(() => validateSbomDocument(dangling, TIMESTAMP), /unknown component/u);
});

test("local path leakage is rejected after normalization", () => {
  const normalized = normalizeSbom(fixture());
  normalized.metadata.component.description = "built in /Users/private/joan";
  assert.throws(() => validateSbomDocument(normalized, TIMESTAMP), /leaks a local path/u);
});
