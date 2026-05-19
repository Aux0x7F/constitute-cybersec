import {
  SURFACE_APP,
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "constitute-protocol";
import {
  buildAppRunnerFulfillment,
} from "constitute-runner";
import {
  buildCybersecProcessorRun,
  cybersecAppContractFixture,
  cybersecBootstrapFixture,
} from "./cybersec-runner-contract.js";
import { defineSurfaceAppContract } from "constitute-ui/surface-app-contract";
import { surfaceAppSelectionReadModel } from "constitute-ui/surface-selection-read-model";
import { createSurfaceModuleRegistry } from "constitute-ui/surface-module-registry";
import { createRuntimeSurfaceClient } from "constitute-ui/runtime-surface-client";
import { prepareCybersecReadModel } from "./cybersec-read-model.js";

const ISSUED_AT = Math.floor(Date.now() / 1_000);

export const cybersecFixture = cybersecAppContractFixture(ISSUED_AT);
export const cybersecBootstrap = cybersecBootstrapFixture(ISSUED_AT);

export const cybersecSurfaceAppContract = assertSurfaceAppContract(cybersecFixture.appContract);
export const cybersecSurfaceApp = defineSurfaceAppContract(cybersecSurfaceAppContract, {
  validate: assertSurfaceAppContract,
});
export const cybersecSurfaceAppManifest = assertSurfaceAppManifest(cybersecFixture.manifest);

export const cybersecProcessorRunReport = buildCybersecProcessorRun(cybersecBootstrap);
export const cybersecRunnerFulfillmentReport = buildAppRunnerFulfillment(cybersecFixture);

export const cybersecSurfaceModuleRegistry = createSurfaceModuleRegistry([
  {
    moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    version: "0.1.0",
    primitiveRefs: ["runtime.attach", "runtime.posture.observe"],
    implementation: Object.freeze({ createRuntimeSurfaceClient }),
  },
  {
    moduleRef: "constitute-cybersec/event-projection-model@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
    version: "0.1.0",
    primitiveRefs: ["event.fabric.processor.contract", "materialization.budget"],
    implementation: Object.freeze({ prepareCybersecReadModel }),
  },
  {
    moduleRef: "constitute-cybersec/product-view@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    version: "0.1.0",
    primitiveRefs: ["runtime.posture.render"],
    implementation: Object.freeze({ surfaceRef: "constitute-cybersec" }),
  },
]);

export const cybersecSurfaceSelectionReadModel = surfaceAppSelectionReadModel({
  surfaceApp: cybersecSurfaceApp,
  manifest: cybersecSurfaceAppManifest,
  moduleRegistry: cybersecSurfaceModuleRegistry,
  moduleRoles: {
    runtimeClient: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    projectionModel: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
    productView: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
  },
  productSurface: "constitute-cybersec",
  runtimeVersion: "0.1.0",
  issuedAt: ISSUED_AT,
  authorityAccessOptions: {
    now: ISSUED_AT,
  },
  runtimeSelectionOptions: {
    authorityAccessOptions: {
      now: ISSUED_AT,
    },
  },
  runnerFulfillmentReport: cybersecRunnerFulfillmentReport,
  serviceManagerOperationOptions: {
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.HEALTH_CHECK,
    operationId: "operation:cybersec:bootstrap-health",
    requestedAt: ISSUED_AT,
  },
  serviceManagerProofDigestOptions: {
    digestId: "proof-digest:cybersec:bootstrap",
    observedAt: ISSUED_AT,
  },
});

export const cybersecProductReadModel = prepareCybersecReadModel({
  fixture: cybersecFixture,
  selectionReadModel: cybersecSurfaceSelectionReadModel,
  cybersecRunReport: cybersecProcessorRunReport,
  runnerFulfillmentReport: cybersecRunnerFulfillmentReport,
});

export const cybersecRuntimeClientModule = cybersecSurfaceModuleRegistry.require(
  cybersecSurfaceApp,
  SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
).implementation;

export const cybersecSurfaceAttachContext = cybersecSurfaceSelectionReadModel.attachContext;
