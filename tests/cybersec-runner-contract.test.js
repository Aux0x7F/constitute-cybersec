import assert from "node:assert/strict";
import { test } from "node:test";
import { assertAppRunnerFulfillmentReport, buildAppRunnerFulfillment } from "constitute-runner";
import {
  assertCybersecProcessorRunReport,
  buildCybersecProcessorRun,
  cybersecAppContractFixture,
  cybersecBootstrapFixture,
  cybersecEventFabricViewFixture,
  deriveCybersecProcessorSeedFromFabric,
} from "../src/cybersec-runner-contract.js";

test("cybersec bootstrap runner emits alert and evidence-hold posture", () => {
  const report = buildCybersecProcessorRun(cybersecBootstrapFixture());
  assert.equal(report.kind, "cybersec.processor.run.report");
  assert.equal(report.eventFabricReport.kind, "event.fabric.processor.report");
  assert.equal(report.eventFabricReport.processorContractRef, "processor-contract:logging.cybersec");
  assert.deepEqual(report.eventFabricReport.observedEventRefs, ["event:runtime:media-path:1"]);
  assert.equal(report.state, "alerted");
  assert.equal(report.processorRef, "constitute-cybersec");
  assert.equal(report.alertPosture.state, "open");
  assert.equal(report.evidenceHoldPosture.state, "holding");
  assert.deepEqual(report.blockedReasons, []);
  assert.equal(report.safeFacts.storageBoundary, "ciphertextFulfillmentOnly");
  assert.equal(report.safeFacts.eventDomainBoundary, "doesNotOwn");
  assertCybersecProcessorRunReport(report);
});

test("cybersec seed derives from authorized event-fabric processor view", () => {
  const view = cybersecEventFabricViewFixture(1_700_000_000);
  const seed = deriveCybersecProcessorSeedFromFabric(view, {
    seedId: "cybersec-seed:test",
    issuedAt: 1_700_000_000,
  });

  assert.equal(seed.seedId, "cybersec-seed:test");
  assert.equal(seed.fabricRef, "event-fabric:logging.default");
  assert.deepEqual(seed.processorContractRefs, ["processor-contract:logging.cybersec"]);
  assert.deepEqual(seed.inputAccessClassRefs, ["event-class:logging.cybersec.encrypted-detail"]);
  assert.deepEqual(seed.accessGroupRefs, ["access-group:logging.cybersec.default"]);
  assert.deepEqual(seed.inputContentClasses, ["encryptedDetail", "safeIndex"]);
  assert.equal(seed.materializationBudgetRefs.includes("logging.cybersec.default.90d"), true);
  assert.equal(seed.semanticBoundaries.eventDomain, "doesNotOwn");

  assert.throws(() => deriveCybersecProcessorSeedFromFabric({
    ...view,
    processorContracts: [],
  }), /missing processor contract/);
});

test("cybersec bootstrap blocks when runner inputs do not match seed access", () => {
  const fixture = cybersecBootstrapFixture();
  const report = buildCybersecProcessorRun({
    ...fixture,
    runnerOperation: {
      ...fixture.runnerOperation,
      inputRefs: ["event-fabric:unrelated"],
    },
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("inputRefMismatch"), true);
  assert.equal(report.accessPosture.state, "blocked");
  assert.equal(report.eventFabricReport.state, "blocked");
  assert.equal(report.eventFabricReport.blockedReasons.includes("inputRefMismatch"), true);
});

test("cybersec bootstrap rejects unsafe safe-fact leakage", () => {
  const fixture = cybersecBootstrapFixture();
  assert.throws(() => buildCybersecProcessorRun({
    ...fixture,
    observedEvents: [{
      eventRef: "event:unsafe",
      eventClass: "runtime.diagnostic",
      severity: "error",
      safeFacts: {
        payload: "must-not-copy",
      },
    }],
  }), /unsafe key payload/);
});

test("cybersec bootstrap blocks expired seed posture", () => {
  const fixture = cybersecBootstrapFixture(1_700_000_000);
  const report = buildCybersecProcessorRun({
    ...fixture,
    now: 1_800_000_000,
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("seedExpired"), true);
  assert.equal(report.blockedReasons.includes("runnerOperationExpired"), true);
  assert.equal(report.eventFabricReport.expiresAt, undefined);
});

test("cybersec app fixture declares event fabric, access, and materialization requirements", () => {
  const now = 1_700_000_000;
  const fixture = cybersecAppContractFixture(now);
  assert.equal(fixture.appContract.appId, "constitute-cybersec");
  assert.equal(fixture.appContract.grantRefs.includes("grant:app:constitute-cybersec:run"), true);
  assert.deepEqual(fixture.appContract.accessGroupRefs, ["access-group:logging.cybersec.default"]);
  assert.deepEqual(fixture.appContract.requiredContentClasses, ["encryptedDetail", "safeIndex"]);
  assert.equal(fixture.appContract.projectionSubscriptions[0].processorRoleRef, "role:cybersec.processor");
  assert.equal(fixture.appContract.materializationBudgets.some((budget) => budget.budgetId === "cybersec.encrypted-detail.refs"), true);
  assert.equal(fixture.appContract.materializationBudgets.some((budget) => budget.budgetId === "cybersec.alerts.ui"), true);

  const report = buildAppRunnerFulfillment(fixture);
  assert.equal(report.state, "succeeded");
  assert.equal(report.appId, "constitute-cybersec");
  assert.equal(report.sourceMode, "bundled");
  assert.equal(report.safeFacts.sourceRefCount, 1);
  assert.equal(report.inputRefs.includes(fixture.seed.seedId), true);
  assertAppRunnerFulfillmentReport(report);
});
