import "constitute-ui/styles.css";
import "./styles.css";
import {
  prepareRuntimeReadModel,
  renderFirstPartyShell,
  setConnectionStateText,
} from "constitute-ui";
import { browserStorageShellContext } from "constitute-ui/runtime-shell-state";
import {
  PLATFORM_RUNTIME_BUILD_ID as RUNTIME_WORKER_BUILD_ID,
  runtimeAttachDebugInfo,
  runtimeSharedWorkerName,
  runtimeWorkerScriptUrl as accountRuntimeWorkerScriptUrl,
} from "../../constitute-account/runtime-contract.js";
import { RUNTIME_DIAGNOSTIC_OPERATOR_PLANES, attachRuntimeDiagnostics } from "../../constitute-account/runtime-diagnostics.js";
import {
  cybersecProductReadModel,
  cybersecRuntimeClientModule,
  cybersecSurfaceAttachContext,
  cybersecSurfaceSelectionReadModel,
} from "./surface-app-contract.js";
import {
  postureRows,
  cybersecSummaryRows,
} from "./cybersec-read-model.js";

const RUNTIME_ATTACH_TIMEOUT_MS = 5_000;
const RUNTIME_WRITE_TIMEOUT_MS = 10_000;

const CYBERSEC_MAIN_HTML = `
  <div class="cybersecMain">
    <section id="cybersecViewOverview" class="cybersecView">
      <section class="cuPanel cybersecHero">
        <div class="cuPanelHeader">
          <div>
            <h2 class="cuPanelTitle">Cybersecurity Processor</h2>
            <p class="cuPanelHint">Contract seed, event fabric, and empty product posture.</p>
          </div>
        </div>
        <div id="cybersecSummary" class="cybersecRows"></div>
      </section>
    </section>
    <section id="cybersecViewContracts" class="cybersecView hidden">
      <div class="cybersecGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Processor</h2></div></div>
          <div id="processorRows" class="cybersecRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Access</h2></div></div>
          <div id="accessRows" class="cybersecRows"></div>
        </section>
      </div>
    </section>
    <section id="cybersecViewMaterialization" class="cybersecView hidden">
      <div class="cybersecGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Alerts</h2></div></div>
          <div id="alertRows" class="cybersecRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Evidence Hold</h2></div></div>
          <div id="evidenceRows" class="cybersecRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Reduction</h2></div></div>
          <div id="reductionRows" class="cybersecRows"></div>
        </section>
      </div>
      <section class="cuPanel cybersecPanel">
        <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Materialization</h2></div></div>
        <div id="materializationRows" class="cybersecRows"></div>
      </section>
    </section>
    <section id="cybersecViewRuntime" class="cybersecView hidden">
      <div class="cybersecGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Runtime</h2></div></div>
          <div id="runtimeRows" class="cybersecRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Instance</h2></div></div>
          <div id="instanceRows" class="cybersecRows"></div>
        </section>
      </div>
    </section>
  </div>
`;

const app = document.querySelector("#app");
if (!app) throw new Error("#app not found");

const shell = renderFirstPartyShell(app, {
  appName: "Cybersecurity",
  navItems: [
    { id: "overview", label: "Overview", active: true },
    { id: "contracts", label: "Contracts" },
    { id: "materialization", label: "Materialization" },
    { id: "runtime", label: "Runtime" },
  ],
  mainHtml: CYBERSEC_MAIN_HTML,
  accountCenterTitle: "",
});

const views = {
  overview: document.getElementById("cybersecViewOverview"),
  contracts: document.getElementById("cybersecViewContracts"),
  materialization: document.getElementById("cybersecViewMaterialization"),
  runtime: document.getElementById("cybersecViewRuntime"),
};

let runtimeClient = null;
let runtimeReadModel = prepareRuntimeReadModel(null, {
  context: browserStorageShellContext(),
  now: Date.now(),
  clientId: "cybersec-ui",
  surface: "constitute-cybersec",
});
let runtimeDiagnosticsAgent = null;
let accountBridgeFrame = null;
let accountBridgePromise = null;
let currentView = "overview";

function runtimeWorkerUrl() {
  return accountRuntimeWorkerScriptUrl(window.location.origin);
}

function accountBridgeUrl() {
  const target = new URL("/constitute-account/", window.location.origin);
  target.searchParams.set("bridge", "1");
  return target.toString();
}

function isRuntimeBrokerUnavailable(error) {
  const message = String(error?.message || error || "").toLowerCase();
  return message.includes("runtime broker unavailable") || message.includes("runtime broker missing");
}

async function ensureAccountBridge() {
  if (accountBridgePromise) return await accountBridgePromise;
  accountBridgePromise = new Promise((resolve) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    accountBridgeFrame = document.getElementById("constituteAccountBridge");
    if (!accountBridgeFrame) {
      const iframe = document.createElement("iframe");
      iframe.id = "constituteAccountBridge";
      iframe.hidden = true;
      iframe.tabIndex = -1;
      iframe.setAttribute("aria-hidden", "true");
      iframe.style.cssText = "position:absolute;width:0;height:0;border:0;opacity:0;pointer-events:none";
      iframe.src = accountBridgeUrl();
      iframe.addEventListener("load", () => window.setTimeout(done, 450), { once: true });
      document.body.appendChild(iframe);
      accountBridgeFrame = iframe;
    } else {
      window.setTimeout(done, 450);
    }
    window.setTimeout(done, 1_500);
  });
  return await accountBridgePromise;
}

function rowList(containerId, rows) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.replaceChildren();
  for (const [label, value] of rows) {
    const item = document.createElement("div");
    item.className = "cybersecRow";
    const key = document.createElement("span");
    key.className = "cybersecRowKey";
    key.textContent = String(label || "");
    const val = document.createElement("span");
    val.className = "cybersecRowValue";
    val.textContent = value === undefined || value === null || value === "" ? "none" : String(value);
    item.append(key, val);
    container.appendChild(item);
  }
}

function renderStaticPosture() {
  rowList("cybersecSummary", cybersecSummaryRows(cybersecProductReadModel));
  rowList("processorRows", postureRows(cybersecProductReadModel, "processor"));
  rowList("accessRows", postureRows(cybersecProductReadModel, "access"));
  rowList("alertRows", postureRows(cybersecProductReadModel, "alert"));
  rowList("evidenceRows", postureRows(cybersecProductReadModel, "evidence"));
  rowList("reductionRows", postureRows(cybersecProductReadModel, "reduction"));
  rowList("materializationRows", postureRows(cybersecProductReadModel, "materialization"));
  rowList("instanceRows", [
    ["Contract", cybersecSurfaceSelectionReadModel.contractId],
    ["Manifest", cybersecSurfaceSelectionReadModel.manifestId],
    ["Source", cybersecSurfaceSelectionReadModel.sourceMode],
    ["Modules", cybersecSurfaceSelectionReadModel.moduleRefs.length],
    ["Runner", cybersecSurfaceSelectionReadModel.runnerFulfillmentReadiness?.state || "unknown"],
    ["Blocked", cybersecSurfaceSelectionReadModel.blockedReasons.join(", ") || "none"],
  ]);
}

function runtimeReadModelOptions() {
  return {
    storage: browserStorageShellContext(),
    context: browserStorageShellContext(),
    now: Date.now(),
    clientId: "cybersec-ui",
    surface: "constitute-cybersec",
  };
}

function renderRuntime(readModel = runtimeReadModel) {
  const model = readModel || prepareRuntimeReadModel(null, runtimeReadModelOptions());
  const shellState = model.shell || {};
  const connection = shellState.connection || {};
  const identity = shellState.identity || {};
  setConnectionStateText(shell.connStateTextEl, {
    label: connection.label || "Offline",
    toneClass: connection.toneClass || "connStateText-offline",
  });
  setConnectionStateText(shell.popConnectionEl, {
    label: connection.label || "Offline",
    toneClass: connection.toneClass || "connStateText-offline",
  });
  if (shell.identityHandleEl) shell.identityHandleEl.textContent = identity.handle || "@unlinked";
  if (shell.popRelayEl) shell.popRelayEl.textContent = shellState.relay?.state || "unknown";
  if (shell.popGatewayEl) shell.popGatewayEl.textContent = shellState.gateway?.state || "unknown";
  if (shell.popServicesEl) shell.popServicesEl.textContent = shellState.services?.state || "unknown";
  if (shell.popConnectionReasonEl) shell.popConnectionReasonEl.textContent = connection.reason || "";
  if (shell.panePathEl) shell.panePathEl.textContent = `Cybersecurity / ${currentView}`;
  rowList("runtimeRows", [
    ["Connection", connection.label],
    ["Runtime", model.buildId || RUNTIME_WORKER_BUILD_ID],
    ["Worker", runtimeSharedWorkerName()],
    ["Read model", model.ready ? "ready" : "pending"],
    ["Target", [model.target?.state || "pending", model.target?.targetRef || ""].filter(Boolean).join(" / ")],
    ["Fabric", [model.fabric?.state || "pending", model.fabric?.planId || ""].filter(Boolean).join(" / ")],
    ["Services", model.serviceRegistry?.serviceCount || 0],
    ["Materialization", model.materialization?.state || "unknown"],
    ["Diagnostics", runtimeDiagnosticsAgent ? "subscribed" : "pending"],
  ]);
  window.__constituteCybersec = {
    selectionReadModel: cybersecSurfaceSelectionReadModel,
    productReadModel: cybersecProductReadModel,
    runtimeReadModel: model,
    activeWork: {
      surface: "constitute-cybersec",
      posture: cybersecProductReadModel.emptyProductPosture.state,
      appId: cybersecProductReadModel.app.appId,
      accessState: cybersecProductReadModel.access.state,
      alertState: cybersecProductReadModel.alert.state,
      evidenceState: cybersecProductReadModel.evidence.state,
    },
  };
}

function selectView(id) {
  currentView = id;
  for (const [viewId, element] of Object.entries(views)) {
    element?.classList.toggle("hidden", viewId !== id);
  }
  for (const button of shell.navButtons || []) {
    button.classList.toggle("active", button.dataset.nav === id);
  }
  renderRuntime();
}

async function attachRuntime() {
  try {
    const createRuntimeSurfaceClient = cybersecRuntimeClientModule.createRuntimeSurfaceClient;
    runtimeClient = createRuntimeSurfaceClient({
      workerUrl: runtimeWorkerUrl(),
      workerName: runtimeSharedWorkerName(),
      clientId: "cybersec-ui",
      surface: "constitute-cybersec",
      attachContext: cybersecSurfaceAttachContext,
      attachTimeoutMs: RUNTIME_ATTACH_TIMEOUT_MS,
      callTimeoutMs: RUNTIME_WRITE_TIMEOUT_MS,
      debugInfo: runtimeAttachDebugInfo(),
      readModelOptions: runtimeReadModelOptions(),
      onReadModel: (readModel) => {
        runtimeReadModel = readModel;
        renderRuntime(readModel);
      },
    });
    runtimeClient.attach();
    await runtimeClient.waitUntilAttached(RUNTIME_ATTACH_TIMEOUT_MS + 500);
  } catch (error) {
    if (!isRuntimeBrokerUnavailable(error)) throw error;
    await ensureAccountBridge();
    return await attachRuntime();
  }
  runtimeDiagnosticsAgent = attachRuntimeDiagnostics({
    port: runtimeClient?.port,
    clientId: "cybersec-ui",
    surface: "constitute-cybersec",
    planes: RUNTIME_DIAGNOSTIC_OPERATOR_PLANES,
  });
  renderRuntime(runtimeClient?.readModel || runtimeReadModel);
}

for (const button of shell.navButtons || []) {
  button.addEventListener("click", () => selectView(button.dataset.activity || "overview"));
}

renderStaticPosture();
renderRuntime(null);
attachRuntime().catch((error) => {
  console.warn("[cybersec-ui] runtime attach failed", error);
  renderRuntime(runtimeReadModel);
});
