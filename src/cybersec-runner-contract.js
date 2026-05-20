import {
  AGREEMENT,
  RUNNER,
  SURFACE_APP,
  SWARM,
  assertCybersecProcessorSeed,
  assertRunnerOperation,
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "constitute-protocol";

export const CYBERSEC_RUN_KIND = "cybersec.processor.run.report";

const ALERT_SEVERITIES = new Set(["critical", "error", "warn"]);
const TERMINAL_BLOCKED_STATES = new Set([
  RUNNER.OPERATION_STATE.BLOCKED,
  RUNNER.OPERATION_STATE.FAILED,
  RUNNER.OPERATION_STATE.REJECTED,
  RUNNER.OPERATION_STATE.CANCELLED,
]);
const UNSAFE_KEY_PATTERN = /^(raw|payload|body|ciphertext|plaintext|secret|token|password|privateKey|seedPhrase|sdp|candidate|mediaBytes|bytes)$/i;

function nowSeconds() {
  return Math.floor(Date.now() / 1_000);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function stringSet(values) {
  return new Set(asArray(values).map((value) => String(value || "").trim()).filter(Boolean));
}

function intersects(left, right) {
  for (const value of left) {
    if (right.has(value)) return true;
  }
  return false;
}

function unique(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function rejectUnsafeSafeFacts(value, context, path = []) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectUnsafeSafeFacts(entry, context, [...path, String(index)]));
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (UNSAFE_KEY_PATTERN.test(key)) {
      throw new Error(`${context} safe facts contain unsafe key ${[...path, key].join(".")}`);
    }
    rejectUnsafeSafeFacts(nested, context, [...path, key]);
  }
}

function normalizeObservedEvent(event, index) {
  const normalized = {
    eventRef: String(event?.eventRef || event?.evidenceRef || event?.eventId || `event:${index}`).trim(),
    eventClass: String(event?.eventClass || "").trim(),
    severity: String(event?.severity || "info").trim().toLowerCase(),
    observedAt: Number(event?.observedAt || 0) || 0,
    safeFacts: event?.safeFacts && typeof event.safeFacts === "object" && !Array.isArray(event.safeFacts)
      ? event.safeFacts
      : {},
  };
  rejectUnsafeSafeFacts(normalized.safeFacts, "observed event");
  return normalized;
}

function cybersecAlertEventActionable(event) {
  return ALERT_SEVERITIES.has(event.severity)
    || event.eventClass.toLowerCase().includes("cybersec");
}

function summarizeSeverity(events) {
  return events.reduce((counts, event) => {
    counts[event.severity] = (counts[event.severity] || 0) + 1;
    return counts;
  }, {});
}

function inputUniverse(seed) {
  return stringSet([
    seed.fabricRef,
    ...asArray(seed.inputAccessClassRefs),
    ...asArray(seed.inputEventClasses),
    ...asArray(seed.inputContentClasses),
    ...asArray(seed.evidenceProfileRefs),
    ...asArray(seed.detailRefs),
  ]);
}

function outputUniverse(seed) {
  return stringSet([
    ...asArray(seed.alertOutputRefs),
    ...asArray(seed.evidenceHoldRefs),
    ...asArray(seed.retentionHoldRefs),
    ...asArray(seed.storageRefs),
  ]);
}

export function cybersecAppContractFixture(now = nowSeconds()) {
  const cybersec = cybersecBootstrapFixture(now);
  const seed = cybersec.seed;
  const appContract = assertSurfaceAppContract({
    contractId: "surface-app:constitute-cybersec@0.1.0",
    schemaVersion: SURFACE_APP.SCHEMA_VERSION,
    appId: "constitute-cybersec",
    appRef: "app:constitute-cybersec",
    version: "0.1.0",
    displayName: "Constitute Cybersecurity",
    requiredPrimitives: [
      "runtime.attach",
      "event.fabric.processor.contract",
      "cybersec.processor.seed",
      "surface.app.authority.access.posture",
    ],
    rootRefs: ["root:aux:primary"],
    deviceRefs: ["device:aux:browser"],
    grantRefs: ["grant:app:constitute-cybersec:run"],
    authorityRefs: ["authority:cybersec.bootstrap"],
    accessGroupRefs: seed.accessGroupRefs,
    requiredContentClasses: seed.inputContentClasses,
    requiredModuleRoles: [
      SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
      SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
      SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    ],
    modules: [
      {
        moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.attach", "runtime.posture.observe"],
        outputs: ["runtime.intent", "adapter.evidence"],
        issuedAt: now,
      },
      {
        moduleRef: "constitute-cybersec/event-projection-model@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["event.fabric.processor.contract", "materialization.budget"],
        inputs: seed.inputAccessClassRefs,
        outputs: ["cybersec.alerts.readModel", "cybersec.evidenceHold.readModel"],
        issuedAt: now,
      },
      {
        moduleRef: "constitute-cybersec/product-view@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.posture.render"],
        inputs: ["cybersec.alerts.readModel", "cybersec.evidenceHold.readModel"],
        outputs: ["cybersec.intent"],
        issuedAt: now,
      },
    ],
    projectionSubscriptions: [
      {
        projectionId: "cybersec.event-fabric",
        channelId: seed.fabricRef,
        processorRoleRef: seed.processorRoleRef,
        inputAccessClassRefs: seed.inputAccessClassRefs,
        inputEventClasses: seed.inputEventClasses,
        inputContentClasses: seed.inputContentClasses,
        accessGroupRefs: seed.accessGroupRefs,
      },
    ],
    permissionRequirements: [
      {
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        grantRefs: ["grant:app:constitute-cybersec:run"],
        actions: ["cybersec.processor.run"],
      },
      {
        plane: AGREEMENT.PLANE.ACCESS_AUTHORITY,
        accessGroupRefs: seed.accessGroupRefs,
        contentClasses: seed.inputContentClasses,
      },
    ],
    capabilityRequirements: [
      {
        capabilityRef: "event.fabric.observe",
        processorRoleRef: seed.processorRoleRef,
        inputAccessClassRefs: seed.inputAccessClassRefs,
      },
      {
        capabilityRef: "cybersec.processor.run",
        seedRef: seed.seedId,
      },
    ],
    materializationBudgets: [
      {
        kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
        budgetId: "cybersec.encrypted-detail.refs",
        sourceAuthority: seed.fabricRef,
        consumerRef: "constitute-cybersec",
        payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.RETAINED_RAW,
        copyRole: SWARM.MATERIALIZATION_COPY_ROLE.REFERENCE_ONLY,
        transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.REFERENCE_ONLY,
        privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.ENCRYPTED_DETAIL,
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        limits: { maxItems: 500, maxBytes: 0 },
        snapshotPolicy: { mode: "referenceOnly", cadence: "onDemand" },
        deltaPolicy: { mode: "eventTimeOrdered" },
        coalescing: { key: "detailRef" },
        cardinality: { maxEventClasses: 16, maxDetailRefs: 500 },
        schema: { state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT, version: "cybersec.detailRefs.v1" },
        referenceRefs: seed.detailRefs,
        issuedAt: now,
      },
      {
        kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
        budgetId: "cybersec.alerts.ui",
        sourceAuthority: seed.fabricRef,
        consumerRef: "constitute-cybersec",
        payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.PROJECTION,
        copyRole: SWARM.MATERIALIZATION_COPY_ROLE.PROJECTION,
        transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE,
        privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.UI_PROJECTION,
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        limits: { maxItems: 100, maxBytes: 128000 },
        snapshotPolicy: { mode: "latest", maxAgeSeconds: 60 },
        deltaPolicy: { mode: "coalesced", key: "alertRef" },
        coalescing: { key: "alertRef" },
        cardinality: { maxAlertRefs: 100, maxSeverityLabels: 8 },
        schema: { state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT, version: "cybersec.alerts.v1" },
        issuedAt: now,
      },
    ],
    serviceManagerPosture: {
      managerId: "manager:constitute-cybersec",
      subjectRef: "app:constitute-cybersec",
      managerRef: "runner:lab-gateway:cybersec-bootstrap",
      state: SURFACE_APP.SERVICE_MANAGER_POSTURE.MANUAL,
      serviceRefs: ["app:constitute-cybersec"],
      capabilityRefs: ["cybersec.processor.run", "event.fabric.observe"],
      grantRefs: ["grant:app:constitute-cybersec:run"],
      authorityRefs: ["authority:cybersec.bootstrap"],
      evidenceRefs: ["build:cybersec:bootstrap"],
      issuedAt: now,
      expiresAt: now + 3600,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
      accessGroupRefs: seed.accessGroupRefs,
      authorityRefs: ["authority:cybersec.bootstrap"],
      detailRefs: seed.detailRefs,
      requiredContentClasses: seed.inputContentClasses,
      evidenceRefs: ["cybersec:access-boundary:bootstrap"],
    },
    updatePosture: { state: SURFACE_APP.UPDATE_POSTURE.STATIC, checkedAt: now },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:cybersec:bootstrap",
      releaseRef: "release:cybersec:bootstrap",
      rollbackRef: "rollback:cybersec:bootstrap",
    },
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const manifest = assertSurfaceAppManifest({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST,
    manifestId: "manifest:constitute-cybersec",
    appId: appContract.appId,
    state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
    currentAppContractRef: appContract.appRef,
    currentVersion: appContract.version,
    defaultSourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    requiredModuleRoles: appContract.requiredModuleRoles,
    bundledSourceRefs: ["bundle:constitute-cybersec@0.1.0"],
    versions: [
      {
        appContractRef: appContract.appRef,
        version: appContract.version,
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        requiredModuleRoles: appContract.requiredModuleRoles,
        bundledSourceRefs: ["bundle:constitute-cybersec@0.1.0"],
        grantRefs: appContract.grantRefs,
        runnerRequirementRefs: ["runner:req:cybersec-bootstrap"],
        serviceManagerRequirementRefs: ["service-manager:req:cybersec-bootstrap"],
        compatibilityRefs: ["protocol:surface-app:v1", "protocol:cybersec-seed:v1"],
        compatibilityWindow: {
          minVersion: "0.1.0",
          maxVersion: "0.1.x",
          protocolRef: "protocol:surface-app:v1",
        },
        bootstrapContractRef: "bootstrap-contract:cybersec-bootstrap",
        releaseContractRef: "release:cybersec:bootstrap",
        authorityRefs: appContract.authorityRefs,
        evidenceRefs: ["build:cybersec:bootstrap", seed.seedId],
        issuedAt: now,
        expiresAt: now + 90 * 24 * 60 * 60,
      },
    ],
    appContractRefs: [appContract.appRef],
    grantRefs: appContract.grantRefs,
    runnerRequirementRefs: ["runner:req:cybersec-bootstrap"],
    serviceManagerRequirementRefs: ["service-manager:req:cybersec-bootstrap"],
    compatibilityRefs: ["protocol:surface-app:v1", "protocol:cybersec-seed:v1"],
    bootstrapContractRefs: ["bootstrap-contract:cybersec-bootstrap"],
    releaseContractRefs: ["release:cybersec:bootstrap"],
    authorityRefs: appContract.authorityRefs,
    evidenceRefs: ["build:cybersec:bootstrap", seed.seedId],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const runnerOperation = assertRunnerOperation({
    ...cybersec.runnerOperation,
    operationId: "runner-operation:cybersec-app:execute:1",
    subjectRef: appContract.appRef,
    contractRef: appContract.appRef,
    grantRefs: appContract.grantRefs,
    inputRefs: [manifest.manifestId, appContract.appRef, seed.seedId],
    outputRefs: ["artifact:cybersec:bootstrap", ...seed.alertOutputRefs, ...seed.evidenceHoldRefs],
    proofRefs: ["proof:cybersec:surface-app"],
    releaseRefs: ["release:cybersec:bootstrap"],
    releaseRef: "release:cybersec:bootstrap",
    rollbackRef: "rollback:cybersec:bootstrap",
    safeFacts: {
      appId: appContract.appId,
      mode: "operatorDev",
      processorRole: seed.processorRoleRef,
    },
  });
  return { appContract, manifest, seed, runnerOperation };
}

export function buildCybersecProcessorRun(input = {}) {
  const seed = assertCybersecProcessorSeed(input.seed);
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const observedAt = Number(input.now || 0) || nowSeconds();
  const observedEvents = [];
  const alertEvents = [];
  asArray(input.observedEvents).forEach((event, index) => {
    const normalized = normalizeObservedEvent(event, index);
    observedEvents.push(normalized);
    if (cybersecAlertEventActionable(normalized)) alertEvents.push(normalized);
  });
  const blockedReasons = [];

  if (seed.state !== "ready") blockedReasons.push(`seed:${seed.state}`);
  if (seed.expiresAt !== undefined && Number(seed.expiresAt || 0) <= observedAt) blockedReasons.push("seedExpired");
  if (seed.processorRoleRef !== "role:cybersec.processor") blockedReasons.push("processorRoleMismatch");
  if (TERMINAL_BLOCKED_STATES.has(runnerOperation.state)) blockedReasons.push(`runnerOperation:${runnerOperation.state}`);
  if (runnerOperation.expiresAt !== undefined && Number(runnerOperation.expiresAt || 0) <= observedAt) blockedReasons.push("runnerOperationExpired");
  if (!intersects(stringSet(runnerOperation.inputRefs), inputUniverse(seed))) blockedReasons.push("inputRefMismatch");
  if (!intersects(stringSet(runnerOperation.outputRefs), outputUniverse(seed))) blockedReasons.push("outputRefMismatch");
  if (asArray(seed.accessGroupRefs).length === 0) blockedReasons.push("missingAccessGroup");
  if (asArray(seed.detailRefs).length === 0) blockedReasons.push("missingDetailRef");
  if (asArray(seed.storageRefs).length === 0) blockedReasons.push("missingStorageRef");

  const heldEventRefs = unique(observedEvents.map((event) => event.eventRef));
  const severityCounts = summarizeSeverity(observedEvents);
  const state = blockedReasons.length
    ? "blocked"
    : alertEvents.length
      ? "alerted"
      : "clear";
  const evidenceRefs = unique([
    ...asArray(seed.evidenceRefs),
    ...asArray(runnerOperation.evidenceRefs),
    ...heldEventRefs,
  ]);
  const safeFacts = {
    threatAnalysisRole: seed.threatAnalysisRole,
    eventCount: observedEvents.length,
    alertCount: alertEvents.length,
    heldEvidenceCount: heldEventRefs.length,
    inputEventClassCount: asArray(seed.inputEventClasses).length,
    inputContentClassCount: asArray(seed.inputContentClasses).length,
    accessGroupCount: asArray(seed.accessGroupRefs).length,
    storageRefCount: asArray(seed.storageRefs).length,
    detailRefCount: asArray(seed.detailRefs).length,
    loggingBoundary: seed.semanticBoundaries?.logging || "",
    storageBoundary: seed.semanticBoundaries?.storage || "",
    eventDomainBoundary: seed.semanticBoundaries?.eventDomain || "",
  };
  rejectUnsafeSafeFacts(safeFacts, "cybersec processor run");
  return assertCybersecProcessorRunReport({
    kind: CYBERSEC_RUN_KIND,
    reportId: `cybersec-run:${seed.seedId}:${runnerOperation.operationId}`,
    seedId: seed.seedId,
    processorRef: seed.processorRef,
    processorRoleRef: seed.processorRoleRef,
    fabricRef: seed.fabricRef,
    runnerOperationId: runnerOperation.operationId,
    state,
    alertPosture: {
      state: blockedReasons.length ? "blocked" : alertEvents.length ? "open" : "clear",
      alertOutputRefs: unique(seed.alertOutputRefs || []),
      alertEventRefs: unique(alertEvents.map((event) => event.eventRef)),
      severityCounts,
    },
    evidenceHoldPosture: {
      state: blockedReasons.length ? "blocked" : heldEventRefs.length ? "holding" : "armed",
      evidenceHoldRefs: unique(seed.evidenceHoldRefs || []),
      retentionHoldRefs: unique(seed.retentionHoldRefs || []),
      heldEventRefs,
    },
    accessPosture: {
      state: blockedReasons.length ? "blocked" : "authorized",
      accessGroupRefs: unique(seed.accessGroupRefs || []),
      inputAccessClassRefs: unique(seed.inputAccessClassRefs || []),
      inputContentClasses: unique(seed.inputContentClasses || []),
      detailRefs: unique(seed.detailRefs || []),
      custodyState: seed.encryptedDetailCustody?.state || "unspecified",
    },
    materializationPosture: {
      state: blockedReasons.length ? "blocked" : "withinBudget",
      materializationBudgetRefs: unique(seed.materializationBudgetRefs || []),
      processorContractRefs: unique(seed.processorContractRefs || []),
      storageRefs: unique(seed.storageRefs || []),
    },
    semanticBoundaries: seed.semanticBoundaries,
    safeFacts,
    evidenceRefs,
    blockedReasons,
    observedAt,
    expiresAt: seed.expiresAt,
  });
}

export function assertCybersecProcessorRunReport(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("cybersec processor run report must be an object");
  if (record.kind !== CYBERSEC_RUN_KIND) throw new Error("invalid cybersec processor run report kind");
  for (const field of ["reportId", "seedId", "processorRef", "processorRoleRef", "fabricRef", "runnerOperationId", "state"]) {
    if (!String(record[field] || "").trim()) throw new Error(`cybersec processor run report missing ${field}`);
  }
  if (!["clear", "alerted", "blocked", "degraded"].includes(record.state)) throw new Error("invalid cybersec processor run report state");
  for (const field of ["alertPosture", "evidenceHoldPosture", "accessPosture", "materializationPosture", "semanticBoundaries", "safeFacts"]) {
    if (!record[field] || typeof record[field] !== "object" || Array.isArray(record[field])) {
      throw new Error(`cybersec processor run report ${field} must be an object`);
    }
  }
  for (const field of ["evidenceRefs", "blockedReasons"]) {
    if (!Array.isArray(record[field])) throw new Error(`cybersec processor run report ${field} must be an array`);
  }
  if (record.state === "blocked" && record.blockedReasons.length === 0) {
    throw new Error("blocked cybersec processor run requires blockedReasons");
  }
  rejectUnsafeSafeFacts(record.safeFacts, "cybersec processor run report");
  if (!Number(record.observedAt || 0)) throw new Error("cybersec processor run report missing observedAt");
  return record;
}

export function cybersecBootstrapFixture(now = nowSeconds()) {
  const seed = assertCybersecProcessorSeed({
    kind: SWARM.RECORD_KIND.CYBERSEC_PROCESSOR_SEED,
    seedId: "cybersec-seed:logging.default",
    fabricRef: "event-fabric:logging.default",
    processorRef: "constitute-cybersec",
    processorRoleRef: "role:cybersec.processor",
    state: "ready",
    threatAnalysisRole: "eventFabricThreatAnalysis",
    inputAccessClassRefs: ["event-class:logging.cybersec.encrypted-detail"],
    inputEventClasses: ["runtime.diagnostic", "media.path"],
    inputContentClasses: ["encryptedDetail", "safeIndex"],
    accessGroupRefs: ["access-group:logging.cybersec.default"],
    processorContractRefs: ["processor-contract:logging.cybersec"],
    evidenceProfileRefs: ["logging.cybersec.default"],
    materializationBudgetRefs: ["logging.cybersec.default.90d"],
    storageRefs: ["storage:logging.cybersec.archive"],
    detailRefs: ["encrypted-detail:logging.default"],
    alertOutputRefs: ["cybersec:alerts:logging.default"],
    evidenceHoldRefs: ["cybersec:evidence-hold:logging.default"],
    retentionHoldRefs: ["retention:cybersec-hold:logging.default"],
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: ["access-group:logging.cybersec.default"],
      detailRefs: ["encrypted-detail:logging.default"],
    },
    semanticBoundaries: {
      logging: "mayConsumeMaterializations",
      storage: "ciphertextFulfillmentOnly",
      eventDomain: "doesNotOwn",
    },
    safeFacts: {
      purpose: "cybersecThreatAnalysis",
      detailCustody: "encryptedDetailRef",
      alerting: "seeded",
    },
    evidenceRefs: ["logging.cybersec.default"],
    blockedReasons: [],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const runnerOperation = assertRunnerOperation({
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: "runner-operation:cybersec-bootstrap:execute:1",
    runnerId: "runner:lab-gateway:cybersec-bootstrap",
    runnerRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:lab-gateway",
    requesterRef: "identity:aux",
    subjectRef: "cybersec-processor:dev",
    contractRef: "cybersec-processor:seed@0.1.0",
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.OPERATION_STATE.SUCCEEDED,
    grantRefs: ["authority-grant:runner:cybersec-bootstrap"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: [seed.fabricRef, ...seed.inputAccessClassRefs],
    outputRefs: [...seed.alertOutputRefs, ...seed.evidenceHoldRefs],
    evidenceRefs: ["evidence:runner:started", "evidence:runner:completed"],
    proofRefs: ["proof:runner:cybersec-bootstrap"],
    releaseRefs: ["release:runner:cybersec-bootstrap"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 512,
      maxCpuPct: 40,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:cybersec-bootstrap",
      profileId: "resource-profile:operator-dev",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 128, cpuPct: 8 },
      budgets: { memoryMiB: 512, cpuPct: 40 },
      sampledAt: now + 3,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED,
    },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:runner:cybersec-bootstrap",
      releaseRef: "release:runner:cybersec-bootstrap",
      rollbackRef: "rollback:runner:cybersec-bootstrap",
    },
    releaseRef: "release:runner:cybersec-bootstrap",
    rollbackRef: "rollback:runner:cybersec-bootstrap",
    safeFacts: {
      role: "cybersecProcessor",
      mode: "operatorDev",
    },
    requestedAt: now,
    acceptedAt: now + 1,
    startedAt: now + 2,
    completedAt: now + 12,
    observedAt: now + 15,
    expiresAt: now + 3600,
  });
  return {
    seed,
    runnerOperation,
    observedEvents: [
      {
        eventRef: "event:runtime:media-path:1",
        eventClass: "media.path",
        severity: "warn",
        observedAt: now + 14,
        safeFacts: {
          posture: "mediaPathBlocked",
          contentClass: "encryptedDetail",
        },
      },
    ],
  };
}
