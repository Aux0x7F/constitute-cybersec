import {
  SURFACE_APP,
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "constitute-protocol";
import {
  buildAppRunnerFulfillment,
  buildSecurityProcessorRun,
  securityAppContractFixture,
  securityBootstrapFixture,
} from "constitute-runner";
import { defineSurfaceAppContract } from "constitute-ui/surface-app-contract";
import { surfaceAppSelectionReadModel } from "constitute-ui/surface-selection-read-model";
import { createSurfaceModuleRegistry } from "constitute-ui/surface-module-registry";
import { createRuntimeSurfaceClient } from "constitute-ui/runtime-surface-client";
import { prepareSecurityReadModel } from "./security-read-model.js";

const ISSUED_AT = Math.floor(Date.now() / 1_000);

export const securityFixture = securityAppContractFixture(ISSUED_AT);
export const securityBootstrap = securityBootstrapFixture(ISSUED_AT);

export const securitySurfaceAppContract = assertSurfaceAppContract(securityFixture.appContract);
export const securitySurfaceApp = defineSurfaceAppContract(securitySurfaceAppContract, {
  validate: assertSurfaceAppContract,
});
export const securitySurfaceAppManifest = assertSurfaceAppManifest(securityFixture.manifest);

export const securityProcessorRunReport = buildSecurityProcessorRun(securityBootstrap);
export const securityRunnerFulfillmentReport = buildAppRunnerFulfillment(securityFixture);

export const securitySurfaceModuleRegistry = createSurfaceModuleRegistry([
  {
    moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    version: "0.1.0",
    primitiveRefs: ["runtime.attach", "runtime.posture.observe"],
    implementation: Object.freeze({ createRuntimeSurfaceClient }),
  },
  {
    moduleRef: "constitute-security/event-projection-model@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
    version: "0.1.0",
    primitiveRefs: ["event.fabric.processor.contract", "materialization.budget"],
    implementation: Object.freeze({ prepareSecurityReadModel }),
  },
  {
    moduleRef: "constitute-security/product-view@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    version: "0.1.0",
    primitiveRefs: ["runtime.posture.render"],
    implementation: Object.freeze({ surfaceRef: "constitute-security" }),
  },
]);

export const securitySurfaceSelectionReadModel = surfaceAppSelectionReadModel({
  surfaceApp: securitySurfaceApp,
  manifest: securitySurfaceAppManifest,
  moduleRegistry: securitySurfaceModuleRegistry,
  moduleRoles: {
    runtimeClient: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    projectionModel: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
    productView: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
  },
  productSurface: "constitute-security",
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
  runnerFulfillmentReport: securityRunnerFulfillmentReport,
  serviceManagerOperationOptions: {
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.HEALTH_CHECK,
    operationId: "operation:security:bootstrap-health",
    requestedAt: ISSUED_AT,
  },
  serviceManagerProofDigestOptions: {
    digestId: "proof-digest:security:bootstrap",
    observedAt: ISSUED_AT,
  },
});

export const securityProductReadModel = prepareSecurityReadModel({
  fixture: securityFixture,
  selectionReadModel: securitySurfaceSelectionReadModel,
  securityRunReport: securityProcessorRunReport,
  runnerFulfillmentReport: securityRunnerFulfillmentReport,
});

export const securityRuntimeClientModule = securitySurfaceModuleRegistry.require(
  securitySurfaceApp,
  SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
).implementation;

export const securitySurfaceAttachContext = securitySurfaceSelectionReadModel.attachContext;
