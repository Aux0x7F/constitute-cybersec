import {
  AGREEMENT,
  LOGGING,
  RUNNER,
  SURFACE_APP,
  SWARM,
  assertCybersecEvidenceHold,
  assertCybersecFinding,
  assertCybersecMitigationRecommendation,
  assertCybersecProcessorSeed,
  assertEventFabricAccessClass,
  assertEventFabricProcessorContract,
  assertEventFabricProcessorReport,
  assertLogEvidenceProfile,
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

export function cybersecEventFabricViewFixture(now = nowSeconds()) {
  const accessClass = assertEventFabricAccessClass({
    kind: SWARM.RECORD_KIND.EVENT_FABRIC_ACCESS_CLASS,
    classId: "event-class:logging.cybersec.encrypted-detail",
    contentClass: AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL,
    privacyTier: AGREEMENT.PRIVACY_TIER.DOMAIN_ENCRYPTED,
    eventClasses: [
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.CYBERSEC_AUDIT,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.RUNTIME_DIAGNOSTIC,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.SERVICE_EVENT,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.STORAGE_ACCESS,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.MEDIA_PATH,
    ],
    accessGroupRefs: ["access-group:logging.cybersec.default"],
    processorRoleRefs: ["role:logging.processor", "role:cybersec.processor"],
    storageClass: "storage:logging.cybersec.archive",
    retentionClass: "rolling.security-evidence",
    safeFactPolicy: "indexOnly",
    indexPolicy: {
      bitemporal: true,
      safeKeys: ["producer.service", "category", "severity", "outcome", "subject.kind"],
      highCardinalityOverflow: "encryptedDetailRef",
    },
    safeFacts: {
      eventView: "security-replay",
      detailCustody: "encryptedDetailRef",
    },
    issuedAt: now,
  });
  const processorContract = assertEventFabricProcessorContract({
    kind: SWARM.RECORD_KIND.EVENT_FABRIC_PROCESSOR_CONTRACT,
    processorContractId: "processor-contract:logging.cybersec",
    fabricRef: "event-fabric:logging.default",
    processorRef: "constitute-cybersec",
    processorRoleRef: "role:cybersec.processor",
    state: "ready",
    inputAccessClassRefs: [accessClass.classId],
    inputEventClasses: accessClass.eventClasses,
    inputContentClasses: [accessClass.contentClass, AGREEMENT.CONTENT_CLASS.SAFE_INDEX],
    outputRefs: [
      "cybersec:findings:logging.default",
      "cybersec:alerts:logging.default",
      "cybersec:evidence-holds:logging.default",
      "retention:cybersec:logging.default",
      "cybersec:mitigation-recommendations:logging.default",
    ],
    storageRefs: ["storage:logging.cybersec.archive"],
    accessGroupRefs: accessClass.accessGroupRefs,
    bitemporalPolicy: {
      eventTimeField: "occurredAt",
      observedTimeField: "receivedAt",
    },
    schemaPolicy: {
      currentVersion: "logging.cybersec.evidence.v1",
      unknownVersionPosture: "holdRefOnly",
    },
    compactionPolicy: {
      snapshotCadence: "storageContainer",
      compactionFloor: "retention-window:90d",
    },
    cardinalityPolicy: {
      rawDetail: "byObjectRef",
      safeFacts: "indexedSummary",
      highCardinalityOverflow: "encryptedDetailRef",
    },
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: accessClass.accessGroupRefs,
      detailRefs: ["encrypted-detail:logging.default"],
    },
    samplingPolicy: {
      state: "adaptive",
      degradeBefore: ["authority", "route", "activation"],
    },
    safeFacts: {
      purpose: "cybersecThreatAnalysis",
      detailCustody: "encryptedDetailRef",
    },
    evidenceRefs: ["logging.cybersec.default"],
    blockedReasons: [],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const evidenceProfile = assertLogEvidenceProfile({
    kind: LOGGING.EVIDENCE_PROFILE_RECORD_KIND,
    profileId: "logging.cybersec.default",
    consumerRef: "constitute-cybersec",
    eventClasses: accessClass.eventClasses,
    retentionWindow: "90d",
    safeIndexRefs: ["logging.events.safeIndex", "logging.dashboard.cybersecSummary"],
    detailCustody: LOGGING.EVIDENCE_DETAIL_CUSTODY.ENCRYPTED_DETAIL_REF,
    encryptedDetailRequired: true,
    accessGrantRefs: ["grant:logging.cybersec.default"],
    storageContainerRefs: ["storage:logging.cybersec.archive"],
    materializationBudgetRef: "logging.cybersec.default.90d",
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  return Object.freeze({
    fabricRef: processorContract.fabricRef,
    accessClasses: Object.freeze([accessClass]),
    processorContracts: Object.freeze([processorContract]),
    evidenceProfiles: Object.freeze([evidenceProfile]),
    retentionHoldRefs: Object.freeze(["retention:cybersec-hold:logging.default"]),
  });
}

export function deriveCybersecProcessorSeedFromFabric(view = {}, options = {}) {
  const now = Number(options.issuedAt || options.now || 0) || nowSeconds();
  const processorRef = String(options.processorRef || "constitute-cybersec");
  const processorRoleRef = String(options.processorRoleRef || "role:cybersec.processor");
  const fabricRef = String(options.fabricRef || view.fabricRef || "event-fabric:logging.default");
  const accessClasses = asArray(view.accessClasses).map(assertEventFabricAccessClass);
  const processorContracts = asArray(view.processorContracts).map(assertEventFabricProcessorContract);
  const evidenceProfiles = asArray(view.evidenceProfiles).map(assertLogEvidenceProfile);
  const selectedContracts = processorContracts.filter((contract) => (
    contract.processorRef === processorRef || contract.processorRoleRef === processorRoleRef
  ));
  if (!selectedContracts.length) {
    throw new Error(`cybersec event fabric view missing processor contract for ${processorRoleRef}`);
  }
  const contractAccessRefs = stringSet(selectedContracts.flatMap((contract) => contract.inputAccessClassRefs));
  const selectedAccessClasses = accessClasses.filter((accessClass) => (
    contractAccessRefs.has(accessClass.classId)
      || asArray(accessClass.processorRoleRefs).includes(processorRoleRef)
  ));
  if (!selectedAccessClasses.length) {
    throw new Error(`cybersec event fabric view missing access class for ${processorRoleRef}`);
  }
  const outputRefs = unique(selectedContracts.flatMap((contract) => contract.outputRefs));
  const detailRefs = unique([
    ...asArray(options.detailRefs),
    ...selectedContracts.flatMap((contract) => asArray(contract.encryptedDetailCustody?.detailRefs)),
    "encrypted-detail:logging.default",
  ]);
  const storageRefs = unique([
    ...asArray(options.storageRefs),
    ...selectedContracts.flatMap((contract) => contract.storageRefs),
    ...evidenceProfiles.flatMap((profile) => profile.storageContainerRefs),
  ]);
  const accessGroupRefs = unique([
    ...selectedAccessClasses.flatMap((accessClass) => accessClass.accessGroupRefs),
    ...selectedContracts.flatMap((contract) => contract.accessGroupRefs),
  ]);
  const seed = assertCybersecProcessorSeed({
    kind: SWARM.RECORD_KIND.CYBERSEC_PROCESSOR_SEED,
    seedId: String(options.seedId || `cybersec-seed:${fabricRef}`),
    fabricRef,
    processorRef,
    processorRoleRef,
    state: "ready",
    threatAnalysisRole: String(options.threatAnalysisRole || "eventFabricThreatAnalysis"),
    inputAccessClassRefs: unique([
      ...selectedContracts.flatMap((contract) => contract.inputAccessClassRefs),
      ...selectedAccessClasses.map((accessClass) => accessClass.classId),
    ]),
    inputEventClasses: unique([
      ...selectedContracts.flatMap((contract) => contract.inputEventClasses),
      ...selectedAccessClasses.flatMap((accessClass) => accessClass.eventClasses),
    ]),
    inputContentClasses: unique([
      ...selectedContracts.flatMap((contract) => contract.inputContentClasses),
      ...selectedAccessClasses.map((accessClass) => accessClass.contentClass),
    ]),
    accessGroupRefs,
    processorContractRefs: unique(selectedContracts.map((contract) => contract.processorContractId)),
    evidenceProfileRefs: unique(evidenceProfiles.map((profile) => profile.profileId)),
    materializationBudgetRefs: unique([
      ...evidenceProfiles.map((profile) => profile.materializationBudgetRef),
      ...selectedContracts.map((contract) => contract.materializationBudget?.budgetId),
      ...asArray(options.materializationBudgetRefs),
    ]),
    storageRefs,
    detailRefs,
    alertOutputRefs: unique([
      ...outputRefs.filter((ref) => ref.startsWith("cybersec:alerts")),
      ...asArray(options.alertOutputRefs),
    ]),
    evidenceHoldRefs: unique([
      ...outputRefs.filter((ref) => ref.startsWith("cybersec:evidence-hold")),
      ...asArray(options.evidenceHoldRefs),
    ]),
    retentionHoldRefs: unique([
      ...asArray(view.retentionHoldRefs),
      ...outputRefs.filter((ref) => ref.startsWith("retention:")),
      ...asArray(options.retentionHoldRefs),
    ]),
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs,
      detailRefs,
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
    evidenceRefs: unique([
      ...evidenceProfiles.map((profile) => profile.profileId),
      ...selectedContracts.flatMap((contract) => contract.evidenceRefs),
    ]),
    blockedReasons: [],
    issuedAt: now,
    expiresAt: Number(options.expiresAt || 0) || now + 90 * 24 * 60 * 60,
  });
  return seed;
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
  const eventFabricReport = assertEventFabricProcessorReport({
    kind: SWARM.RECORD_KIND.EVENT_FABRIC_PROCESSOR_REPORT,
    reportId: `event-fabric-report:${seed.seedId}:${runnerOperation.operationId}`,
    processorContractRef: asArray(seed.processorContractRefs)[0] || seed.seedId,
    fabricRef: seed.fabricRef,
    processorRef: seed.processorRef,
    processorRoleRef: seed.processorRoleRef,
    runnerOperationRef: runnerOperation.operationId,
    state,
    inputRefs: unique(runnerOperation.inputRefs || []),
    outputRefs: unique(runnerOperation.outputRefs || []),
    inputAccessClassRefs: unique(seed.inputAccessClassRefs || []),
    inputEventClasses: unique(seed.inputEventClasses || []),
    inputContentClasses: unique(seed.inputContentClasses || []),
    accessGroupRefs: unique(seed.accessGroupRefs || []),
    observedEventRefs: unique(observedEvents.map((event) => event.eventRef)),
    heldEventRefs,
    storageRefs: unique(seed.storageRefs || []),
    findingRefs: alertEvents.length ? [`cybersec:finding:${seed.seedId}:media-path`] : [],
    alertRefs: unique(alertEvents.map((event) => `cybersec:alert:${event.eventRef}`)),
    evidenceHoldRefs: heldEventRefs.length ? unique(seed.evidenceHoldRefs || []) : [],
    retentionDemandRefs: heldEventRefs.length ? unique(seed.retentionHoldRefs || []) : [],
    mitigationRecommendationRefs: alertEvents.length
      ? [`cybersec:recommendation:${seed.seedId}:request-evidence`]
      : [],
    safeFacts,
    evidenceRefs,
    blockedReasons,
    observedAt,
    expiresAt: Number(seed.expiresAt || 0) > observedAt ? seed.expiresAt : undefined,
  });
  const findingRecords = eventFabricReport.findingRefs.map((findingRef) => assertCybersecFinding({
    kind: SWARM.RECORD_KIND.CYBERSEC_FINDING,
    findingId: findingRef,
    processorReportRef: eventFabricReport.reportId,
    processorRef: seed.processorRef,
    processorRoleRef: seed.processorRoleRef,
    subjectRef: seed.fabricRef,
    findingKind: "eventFabricAnomaly",
    severity: alertEvents.some((event) => event.severity === "critical") ? "critical" : "medium",
    state: blockedReasons.length ? "blocked" : "open",
    confidenceScore: alertEvents.length ? 0.72 : 0,
    inputAccessClassRefs: unique(seed.inputAccessClassRefs || []),
    observedEventRefs: unique(alertEvents.map((event) => event.eventRef)),
    accessGroupRefs: unique(seed.accessGroupRefs || []),
    evidenceRefs: [eventFabricReport.reportId, ...unique(alertEvents.map((event) => event.eventRef))],
    evidenceHoldRefs: eventFabricReport.evidenceHoldRefs,
    retentionDemandRefs: eventFabricReport.retentionDemandRefs,
    mitigationRecommendationRefs: eventFabricReport.mitigationRecommendationRefs,
    safeFacts: {
      findingKind: "eventFabricAnomaly",
      severity: alertEvents.some((event) => event.severity === "critical") ? "critical" : "medium",
      alertEventCount: alertEvents.length,
    },
    blockedReasons,
    observedAt,
    expiresAt: Number(seed.expiresAt || 0) > observedAt ? seed.expiresAt : undefined,
  }));
  const evidenceHoldRecords = eventFabricReport.evidenceHoldRefs.map((holdRef) => assertCybersecEvidenceHold({
    kind: SWARM.RECORD_KIND.CYBERSEC_EVIDENCE_HOLD,
    holdId: holdRef,
    findingRef: eventFabricReport.findingRefs[0] || `cybersec:finding:${seed.seedId}:none`,
    processorReportRef: eventFabricReport.reportId,
    subjectRef: seed.fabricRef,
    state: blockedReasons.length ? "blocked" : "holding",
    eventRefs: heldEventRefs,
    detailRefs: unique(seed.detailRefs || []),
    storageRefs: unique(seed.storageRefs || []),
    retentionDemandRefs: eventFabricReport.retentionDemandRefs,
    accessGroupRefs: unique(seed.accessGroupRefs || []),
    evidenceRefs: [eventFabricReport.reportId, ...heldEventRefs],
    safeFacts: {
      heldEventCount: heldEventRefs.length,
      detailRefCount: asArray(seed.detailRefs).length,
      storageRefCount: asArray(seed.storageRefs).length,
    },
    blockedReasons,
    issuedAt: observedAt,
    expiresAt: Number(seed.expiresAt || 0) > observedAt ? seed.expiresAt : undefined,
  }));
  const mitigationRecommendationRecords = eventFabricReport.mitigationRecommendationRefs.map((recommendationRef) => assertCybersecMitigationRecommendation({
    kind: SWARM.RECORD_KIND.CYBERSEC_MITIGATION_RECOMMENDATION,
    recommendationId: recommendationRef,
    findingRef: eventFabricReport.findingRefs[0] || `cybersec:finding:${seed.seedId}:none`,
    processorReportRef: eventFabricReport.reportId,
    recommenderRef: seed.processorRef,
    actionKind: "requestEvidence",
    targetRef: seed.fabricRef,
    state: blockedReasons.length ? "blocked" : "recommended",
    authorityRefs: ["authority:cybersec.bootstrap"],
    consumerRefs: ["constitute-gateway", "constitute-moderation"],
    evidenceRefs: [eventFabricReport.reportId],
    safeFacts: {
      recommendationOnly: true,
      enforcementOwner: "consumer",
    },
    blockedReasons,
    issuedAt: observedAt,
    expiresAt: Number(seed.expiresAt || 0) > observedAt ? seed.expiresAt : undefined,
  }));
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
    eventFabricReport,
    findingRecords,
    evidenceHoldRecords,
    mitigationRecommendationRecords,
    safeFacts,
    evidenceRefs,
    blockedReasons,
    observedAt,
    expiresAt: Number(seed.expiresAt || 0) > observedAt ? seed.expiresAt : undefined,
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
  assertEventFabricProcessorReport(record.eventFabricReport);
  asArray(record.findingRecords).forEach(assertCybersecFinding);
  asArray(record.evidenceHoldRecords).forEach(assertCybersecEvidenceHold);
  asArray(record.mitigationRecommendationRecords).forEach(assertCybersecMitigationRecommendation);
  if (record.state === "blocked" && record.blockedReasons.length === 0) {
    throw new Error("blocked cybersec processor run requires blockedReasons");
  }
  rejectUnsafeSafeFacts(record.safeFacts, "cybersec processor run report");
  if (!Number(record.observedAt || 0)) throw new Error("cybersec processor run report missing observedAt");
  return record;
}

export function cybersecBootstrapFixture(now = nowSeconds()) {
  const eventFabricView = cybersecEventFabricViewFixture(now);
  const seed = deriveCybersecProcessorSeedFromFabric(eventFabricView, {
    seedId: "cybersec-seed:logging.default",
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
    outputRefs: [...seed.alertOutputRefs, ...seed.evidenceHoldRefs, ...seed.retentionHoldRefs],
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
