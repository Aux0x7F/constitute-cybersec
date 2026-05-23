const EMPTY_PRODUCT_POSTURE = Object.freeze({
  kind: "cybersec.product.posture",
  state: "emptyProductPosture",
  reason: "cybersec processor runway is seeded; threat workflows are not built",
});

export function prepareCybersecReadModel({
  fixture,
  selectionReadModel,
  cybersecRunReport,
  runnerFulfillmentReport,
} = {}) {
  const seed = fixture?.seed || {};
  const appContract = fixture?.appContract || {};
  const materialization = cybersecRunReport?.materializationPosture || {};
  const alert = cybersecRunReport?.alertPosture || {};
  const evidence = cybersecRunReport?.evidenceHoldPosture || {};
  const access = cybersecRunReport?.accessPosture || {};
  const reduction = cybersecRunReport?.reductionProfilePosture || {};

  return deepFreeze({
    kind: "cybersec.surface.readModel",
    state: selectionReadModel?.state || "unknown",
    app: {
      appId: appContract.appId || "",
      appRef: appContract.appRef || "",
      version: appContract.version || "",
      contractId: appContract.contractId || "",
      sourceMode: selectionReadModel?.sourceMode || "",
      moduleRefs: selectionReadModel?.moduleRefs || [],
      materializationBudgetRefs: selectionReadModel?.materializationBudgetRefs || [],
    },
    processor: {
      seedId: seed.seedId || "",
      processorRef: seed.processorRef || "",
      processorRoleRef: seed.processorRoleRef || "",
      fabricRef: seed.fabricRef || "",
      state: seed.state || "",
      inputEventClasses: seed.inputEventClasses || [],
      inputContentClasses: seed.inputContentClasses || [],
      inputAccessClassRefs: seed.inputAccessClassRefs || [],
    },
    access: {
      state: access.state || "unknown",
      accessGroupRefs: access.accessGroupRefs || seed.accessGroupRefs || [],
      detailRefs: access.detailRefs || seed.detailRefs || [],
      custodyState: access.custodyState || seed.encryptedDetailCustody?.state || "",
    },
    alert: {
      state: alert.state || "unknown",
      alertOutputRefs: alert.alertOutputRefs || seed.alertOutputRefs || [],
      alertEventRefs: alert.alertEventRefs || [],
      severityCounts: alert.severityCounts || {},
    },
    reduction: {
      state: reduction.state || "unknown",
      profileRefs: reduction.profileRefs || [],
      ruleRefs: reduction.ruleRefs || [],
      findingKinds: reduction.findingKinds || [],
      actionKinds: reduction.actionKinds || [],
      matchedEventRefs: reduction.matchedEventRefs || [],
    },
    evidence: {
      state: evidence.state || "unknown",
      evidenceHoldRefs: evidence.evidenceHoldRefs || seed.evidenceHoldRefs || [],
      retentionHoldRefs: evidence.retentionHoldRefs || seed.retentionHoldRefs || [],
      heldEventRefs: evidence.heldEventRefs || [],
    },
    materialization: {
      state: materialization.state || "unknown",
      materializationBudgetRefs: materialization.materializationBudgetRefs || seed.materializationBudgetRefs || [],
      storageRefs: cybersecRunReport?.storageRefs || seed.storageRefs || [],
    },
    runner: {
      state: runnerFulfillmentReport?.state || "unknown",
      runnerId: runnerFulfillmentReport?.runnerId || "",
      hostRef: runnerFulfillmentReport?.hostRef || "",
      operation: runnerFulfillmentReport?.operation || "",
      sourceMode: runnerFulfillmentReport?.sourceMode || "",
      outputRefs: runnerFulfillmentReport?.outputRefs || [],
      proofRefs: runnerFulfillmentReport?.proofRefs || [],
      releaseRefs: runnerFulfillmentReport?.releaseRefs || [],
      resourcePosture: runnerFulfillmentReport?.resourcePosture || null,
    },
    emptyProductPosture: EMPTY_PRODUCT_POSTURE,
    blockedReasons: selectionReadModel?.blockedReasons || [],
  });
}

export function cybersecSummaryRows(model) {
  return [
    ["App", `${model.app.appId}@${model.app.version}`],
    ["Selection", model.state],
    ["Processor", `${model.processor.processorRef} (${model.processor.state})`],
    ["Fabric", model.processor.fabricRef],
    ["Access", model.access.state],
    ["Alerts", model.alert.state],
    ["Reduction", model.reduction.state],
    ["Evidence hold", model.evidence.state],
    ["Materialization", model.materialization.state],
    ["Runner", model.runner.state],
    ["Product", model.emptyProductPosture.state],
  ];
}

export function postureRows(model, key) {
  const value = model?.[key] || {};
  if (key === "processor") {
    return [
      ["Seed", value.seedId],
      ["Role", value.processorRoleRef],
      ["Events", value.inputEventClasses.join(", ")],
      ["Content", value.inputContentClasses.join(", ")],
      ["Access classes", value.inputAccessClassRefs.join(", ")],
    ];
  }
  if (key === "access") {
    return [
      ["State", value.state],
      ["Groups", value.accessGroupRefs.join(", ")],
      ["Details", value.detailRefs.join(", ")],
      ["Custody", value.custodyState],
    ];
  }
  if (key === "alert") {
    return [
      ["State", value.state],
      ["Outputs", value.alertOutputRefs.join(", ")],
      ["Events", value.alertEventRefs.length],
      ["Severity", severityText(value.severityCounts)],
    ];
  }
  if (key === "evidence") {
    return [
      ["State", value.state],
      ["Holds", value.evidenceHoldRefs.join(", ")],
      ["Retention", value.retentionHoldRefs.join(", ")],
      ["Held events", value.heldEventRefs.length],
    ];
  }
  if (key === "reduction") {
    return [
      ["State", value.state],
      ["Profiles", value.profileRefs.join(", ")],
      ["Rules", value.ruleRefs.join(", ")],
      ["Findings", value.findingKinds.join(", ")],
      ["Events", value.matchedEventRefs.length],
    ];
  }
  if (key === "materialization") {
    return [
      ["State", value.state],
      ["Budgets", value.materializationBudgetRefs.join(", ")],
      ["Storage", value.storageRefs.join(", ")],
    ];
  }
  return [];
}

function severityText(counts = {}) {
  const entries = Object.entries(counts).filter(([, count]) => Number(count) > 0);
  return entries.length ? entries.map(([key, count]) => `${key}:${count}`).join(" ") : "none";
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}
