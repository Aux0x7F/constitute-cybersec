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
  assert.deepEqual(report.eventFabricReport.findingRefs, ["cybersec:finding:cybersec-seed:logging.default:media-path"]);
  assert.deepEqual(report.eventFabricReport.evidenceHoldRefs, ["cybersec:evidence-holds:logging.default"]);
  assert.deepEqual(report.eventFabricReport.retentionDemandRefs, [
    "retention:cybersec-hold:logging.default",
    "retention:cybersec:logging.default",
  ]);
  assert.deepEqual(report.eventFabricReport.mitigationRecommendationRefs, ["cybersec:recommendation:cybersec-seed:logging.default:request-evidence"]);
  assert.equal(report.findingRecords.length, 1);
  assert.equal(report.findingRecords[0].state, "open");
  assert.equal(report.findingRecords[0].severity, "medium");
  assert.equal(report.evidenceHoldRecords.length, 1);
  assert.equal(report.evidenceHoldRecords[0].state, "holding");
  assert.equal(report.mitigationRecommendationRecords.length, 1);
  assert.equal(report.mitigationRecommendationRecords[0].actionKind, "requestEvidence");
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
  assert.deepEqual(seed.retentionHoldRefs, [
    "retention:cybersec-hold:logging.default",
    "retention:cybersec:logging.default",
  ]);
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

test("cybersec adversarial fixture keeps hostile route evidence as recommendation-only posture", () => {
  const now = 1_700_000_000;
  const fixture = cybersecBootstrapFixture(now);
  const report = buildCybersecProcessorRun({
    ...fixture,
    now: now + 100,
    observedEvents: [
      ...fixture.observedEvents,
      {
        eventRef: "event:route:hostile-member:1",
        eventClass: "runtime.route.observation",
        severity: "critical",
        observedAt: now + 99,
        safeFacts: {
          posture: "routeMemberMismatch",
          outcome: "suspiciousMember",
          subjectKind: "route",
        },
      },
    ],
  });

  assert.equal(report.state, "alerted");
  assert.equal(report.findingRecords[0].severity, "critical");
  assert.equal(report.findingRecords[0].observedEventRefs.includes("event:route:hostile-member:1"), true);
  assert.equal(report.evidenceHoldRecords[0].eventRefs.includes("event:route:hostile-member:1"), true);
  assert.deepEqual(report.evidenceHoldRecords[0].retentionDemandRefs, [
    "retention:cybersec-hold:logging.default",
    "retention:cybersec:logging.default",
  ]);
  assert.equal(report.mitigationRecommendationRecords[0].state, "recommended");
  assert.equal(report.mitigationRecommendationRecords[0].safeFacts.recommendationOnly, true);
  assert.equal(report.mitigationRecommendationRecords[0].safeFacts.enforcementOwner, "consumer");
  assert.equal(JSON.stringify(report).includes("plaintext"), false);
});

test("cybersec adversarial fixture blocks missing encrypted-detail authority and custody", () => {
  const now = 1_700_000_000;
  const fixture = cybersecBootstrapFixture(now);
  const report = buildCybersecProcessorRun({
    ...fixture,
    now: now + 100,
    seed: {
      ...fixture.seed,
      accessGroupRefs: [],
      detailRefs: [],
      storageRefs: [],
    },
  });

  assert.equal(report.state, "blocked");
  assert.deepEqual(report.blockedReasons, ["missingAccessGroup", "missingDetailRef", "missingStorageRef"]);
  assert.equal(report.accessPosture.state, "blocked");
  assert.equal(report.eventFabricReport.state, "blocked");
  assert.equal(report.findingRecords[0].state, "blocked");
  assert.equal(report.evidenceHoldRecords[0].state, "blocked");
  assert.equal(report.mitigationRecommendationRecords[0].state, "blocked");
});

test("cybersec adversarial fixture rejects nested plaintext safe-fact fields", () => {
  const fixture = cybersecBootstrapFixture();
  assert.throws(() => buildCybersecProcessorRun({
    ...fixture,
    observedEvents: [{
      eventRef: "event:unsafe:nested",
      eventClass: "runtime.diagnostic",
      severity: "error",
      safeFacts: {
        nested: {
          plaintext: "must-not-copy",
        },
      },
    }],
  }), /unsafe key nested\.plaintext/);
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
