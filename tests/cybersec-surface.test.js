import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  cybersecProductReadModel,
  cybersecProcessorRunReport,
  cybersecRunnerFulfillmentReport,
  cybersecSurfaceAppContract,
  cybersecSurfaceSelectionReadModel,
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

test("Cybersec surface declares the event-fabric processor contract posture", () => {
  assert.equal(cybersecSurfaceAppContract.appId, "constitute-cybersec");
  assert.equal(cybersecSurfaceSelectionReadModel.state, "ready");
  assert.equal(cybersecProductReadModel.emptyProductPosture.state, "emptyProductPosture");
  assert.deepEqual(cybersecSurfaceSelectionReadModel.blockedReasons, []);
  assert.ok(cybersecSurfaceAppContract.requiredPrimitives.includes("cybersec.processor.seed"));
  assert.ok(cybersecProductReadModel.access.accessGroupRefs.includes("access-group:logging.cybersec.default"));
  assert.ok(cybersecProductReadModel.materialization.storageRefs.includes("storage:logging.cybersec.archive"));
});

test("Cybersec runway materializes alert and evidence-hold posture without raw details", () => {
  assert.equal(cybersecProcessorRunReport.state, "alerted");
  assert.equal(cybersecProcessorRunReport.alertPosture.state, "open");
  assert.equal(cybersecProcessorRunReport.evidenceHoldPosture.state, "holding");
  assert.equal(cybersecProcessorRunReport.materializationPosture.state, "withinBudget");
  assert.equal(cybersecRunnerFulfillmentReport.state, "succeeded");
  assertNoUnsafeDetailKeys(cybersecProcessorRunReport);
  assert.equal(JSON.stringify(cybersecProcessorRunReport).includes("plaintext"), false);
});

test("Cybersecurity UI imports shared runtime helpers and does not construct route frames", () => {
  const source = readFileSync(resolve("src/main.js"), "utf8");
  assert.match(source, /\.\.\/\.\.\/constitute-account\/runtime-contract\.js/);
  assert.match(source, /createRuntimeSurfaceClient/);
  assert.match(source, /prepareRuntimeReadModel/);
  assert.doesNotMatch(source, /\bruntimeSnapshot\b/);
  assert.doesNotMatch(source, /SwarmFrame|makeSwarmFrame|makeService|stream\.session\.(?:intent|offer|answer|candidate|control|close|health)/);
});
