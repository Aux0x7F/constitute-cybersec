import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  securityProductReadModel,
  securityProcessorRunReport,
  securityRunnerFulfillmentReport,
  securitySurfaceAppContract,
  securitySurfaceSelectionReadModel,
} from "../src/surface-app-contract.js";

const UNSAFE_DETAIL_KEYS = new Set([
  "raw",
  "payload",
  "body",
  "plaintext",
  "secret",
  "token",
  "privateKey",
  "sdp",
  "candidate",
  "mediaBytes",
  "bytes",
]);

function assertNoUnsafeDetailKeys(value, path = []) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(UNSAFE_DETAIL_KEYS.has(key), false, `unsafe key ${[...path, key].join(".")}`);
    assertNoUnsafeDetailKeys(child, [...path, key]);
  }
}

test("Security surface declares the event-fabric processor contract posture", () => {
  assert.equal(securitySurfaceAppContract.appId, "constitute-security");
  assert.equal(securitySurfaceSelectionReadModel.state, "ready");
  assert.equal(securityProductReadModel.emptyProductPosture.state, "emptyProductPosture");
  assert.deepEqual(securitySurfaceSelectionReadModel.blockedReasons, []);
  assert.ok(securitySurfaceAppContract.requiredPrimitives.includes("security.processor.seed"));
  assert.ok(securityProductReadModel.access.accessGroupRefs.includes("access-group:logging.security.default"));
  assert.ok(securityProductReadModel.materialization.storageRefs.includes("storage:logging.security.archive"));
});

test("Security runway materializes alert and evidence-hold posture without raw details", () => {
  assert.equal(securityProcessorRunReport.state, "alerted");
  assert.equal(securityProcessorRunReport.alertPosture.state, "open");
  assert.equal(securityProcessorRunReport.evidenceHoldPosture.state, "holding");
  assert.equal(securityProcessorRunReport.materializationPosture.state, "withinBudget");
  assert.equal(securityRunnerFulfillmentReport.state, "succeeded");
  assertNoUnsafeDetailKeys(securityProcessorRunReport);
  assert.equal(JSON.stringify(securityProcessorRunReport).includes("plaintext"), false);
});

test("Security UI imports shared runtime helpers and does not construct route frames", () => {
  const source = readFileSync(resolve("src/main.js"), "utf8");
  assert.match(source, /\.\.\/\.\.\/constitute-account\/runtime-contract\.js/);
  assert.match(source, /createRuntimeSurfaceClient/);
  assert.doesNotMatch(source, /SwarmFrame|makeSwarmFrame|makeService|stream\.session\.(?:intent|offer|answer|candidate|control|close|health)/);
});
