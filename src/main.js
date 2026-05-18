import "constitute-ui/styles.css";
import "./styles.css";
import {
  renderFirstPartyShell,
  setConnectionStateText,
} from "constitute-ui";
import {
  browserStorageShellContext,
  deriveRuntimeShellState,
} from "constitute-ui/runtime-shell-state";
import {
  PLATFORM_RUNTIME_BUILD_ID as RUNTIME_WORKER_BUILD_ID,
  runtimeAttachDebugInfo,
  runtimeSharedWorkerName,
  runtimeWorkerScriptUrl as accountRuntimeWorkerScriptUrl,
} from "../../constitute-account/runtime-contract.js";
import { RUNTIME_DIAGNOSTIC_OPERATOR_PLANES, attachRuntimeDiagnostics } from "../../constitute-account/runtime-diagnostics.js";
import {
  securityProductReadModel,
  securityRuntimeClientModule,
  securitySurfaceAttachContext,
  securitySurfaceSelectionReadModel,
} from "./surface-app-contract.js";
import {
  postureRows,
  securitySummaryRows,
} from "./security-read-model.js";

const RUNTIME_ATTACH_TIMEOUT_MS = 5_000;
const RUNTIME_WRITE_TIMEOUT_MS = 10_000;

const SECURITY_MAIN_HTML = `
  <div class="securityMain">
    <section id="securityViewOverview" class="securityView">
      <section class="cuPanel securityHero">
        <div class="cuPanelHeader">
          <div>
            <h2 class="cuPanelTitle">Security Processor</h2>
            <p class="cuPanelHint">Contract seed, event fabric, and empty product posture.</p>
          </div>
        </div>
        <div id="securitySummary" class="securityRows"></div>
      </section>
    </section>
    <section id="securityViewContracts" class="securityView hidden">
      <div class="securityGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Processor</h2></div></div>
          <div id="processorRows" class="securityRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Access</h2></div></div>
          <div id="accessRows" class="securityRows"></div>
        </section>
      </div>
    </section>
    <section id="securityViewMaterialization" class="securityView hidden">
      <div class="securityGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Alerts</h2></div></div>
          <div id="alertRows" class="securityRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Evidence Hold</h2></div></div>
          <div id="evidenceRows" class="securityRows"></div>
        </section>
      </div>
      <section class="cuPanel securityPanel">
        <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Materialization</h2></div></div>
        <div id="materializationRows" class="securityRows"></div>
      </section>
    </section>
    <section id="securityViewRuntime" class="securityView hidden">
      <div class="securityGrid">
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Runtime</h2></div></div>
          <div id="runtimeRows" class="securityRows"></div>
        </section>
        <section class="cuPanel">
          <div class="cuPanelHeader"><div><h2 class="cuPanelTitle">Instance</h2></div></div>
          <div id="instanceRows" class="securityRows"></div>
        </section>
      </div>
    </section>
  </div>
`;

const app = document.querySelector("#app");
if (!app) throw new Error("#app not found");

const shell = renderFirstPartyShell(app, {
  appName: "Security",
  navItems: [
    { id: "overview", label: "Overview", active: true },
    { id: "contracts", label: "Contracts" },
    { id: "materialization", label: "Materialization" },
    { id: "runtime", label: "Runtime" },
  ],
  mainHtml: SECURITY_MAIN_HTML,
  accountCenterTitle: "",
});

const views = {
  overview: document.getElementById("securityViewOverview"),
  contracts: document.getElementById("securityViewContracts"),
  materialization: document.getElementById("securityViewMaterialization"),
  runtime: document.getElementById("securityViewRuntime"),
};

let runtimeClient = null;
let runtimeSnapshot = null;
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
    item.className = "securityRow";
    const key = document.createElement("span");
    key.className = "securityRowKey";
    key.textContent = String(label || "");
    const val = document.createElement("span");
    val.className = "securityRowValue";
    val.textContent = value === undefined || value === null || value === "" ? "none" : String(value);
    item.append(key, val);
    container.appendChild(item);
  }
}

function renderStaticPosture() {
  rowList("securitySummary", securitySummaryRows(securityProductReadModel));
  rowList("processorRows", postureRows(securityProductReadModel, "processor"));
  rowList("accessRows", postureRows(securityProductReadModel, "access"));
  rowList("alertRows", postureRows(securityProductReadModel, "alert"));
  rowList("evidenceRows", postureRows(securityProductReadModel, "evidence"));
  rowList("materializationRows", postureRows(securityProductReadModel, "materialization"));
  rowList("instanceRows", [
    ["Contract", securitySurfaceSelectionReadModel.contractId],
    ["Manifest", securitySurfaceSelectionReadModel.manifestId],
    ["Source", securitySurfaceSelectionReadModel.sourceMode],
    ["Modules", securitySurfaceSelectionReadModel.moduleRefs.length],
    ["Runner", securitySurfaceSelectionReadModel.runnerFulfillmentReadiness?.state || "unknown"],
    ["Blocked", securitySurfaceSelectionReadModel.blockedReasons.join(", ") || "none"],
  ]);
}

function renderRuntime(snapshot = runtimeSnapshot) {
  const shellState = deriveRuntimeShellState(snapshot, {
    storage: browserStorageShellContext(),
    now: Date.now(),
  });
  setConnectionStateText(shell.connStateTextEl, {
    label: shellState.connectionLabel,
    toneClass: shellState.connectionToneClass,
  });
  setConnectionStateText(shell.popConnectionEl, {
    label: shellState.connectionLabel,
    toneClass: shellState.connectionToneClass,
  });
  if (shell.identityHandleEl) shell.identityHandleEl.textContent = shellState.identityHandle;
  if (shell.panePathEl) shell.panePathEl.textContent = `Security / ${currentView}`;
  rowList("runtimeRows", [
    ["Connection", shellState.connectionLabel],
    ["Runtime", RUNTIME_WORKER_BUILD_ID],
    ["Worker", runtimeSharedWorkerName()],
    ["Snapshot", snapshot ? "received" : "pending"],
    ["Diagnostics", runtimeDiagnosticsAgent ? "subscribed" : "pending"],
  ]);
  window.__constituteSecurity = {
    selectionReadModel: securitySurfaceSelectionReadModel,
    productReadModel: securityProductReadModel,
    runtimeSnapshot: snapshot || null,
    activeWork: {
      surface: "constitute-security",
      posture: securityProductReadModel.emptyProductPosture.state,
      appId: securityProductReadModel.app.appId,
      accessState: securityProductReadModel.access.state,
      alertState: securityProductReadModel.alert.state,
      evidenceState: securityProductReadModel.evidence.state,
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
    const createRuntimeSurfaceClient = securityRuntimeClientModule.createRuntimeSurfaceClient;
    runtimeClient = createRuntimeSurfaceClient({
      workerUrl: runtimeWorkerUrl(),
      sharedWorkerName: runtimeSharedWorkerName(),
      clientId: "security-ui",
      surface: "constitute-security",
      attachContext: securitySurfaceAttachContext,
      attachTimeoutMs: RUNTIME_ATTACH_TIMEOUT_MS,
      writeTimeoutMs: RUNTIME_WRITE_TIMEOUT_MS,
      debugInfo: runtimeAttachDebugInfo(),
    });
    runtimeSnapshot = await runtimeClient.attach();
  } catch (error) {
    if (!isRuntimeBrokerUnavailable(error)) throw error;
    await ensureAccountBridge();
    return await attachRuntime();
  }
  runtimeDiagnosticsAgent = attachRuntimeDiagnostics(runtimeClient, {
    clientId: "security-ui",
    surface: "constitute-security",
    planes: RUNTIME_DIAGNOSTIC_OPERATOR_PLANES,
  });
  runtimeClient.subscribeSnapshot?.((snapshot) => {
    runtimeSnapshot = snapshot;
    renderRuntime(snapshot);
  });
  renderRuntime(runtimeSnapshot);
}

for (const button of shell.navButtons || []) {
  button.addEventListener("click", () => selectView(button.dataset.nav || "overview"));
}

renderStaticPosture();
renderRuntime(null);
attachRuntime().catch((error) => {
  console.warn("[security-ui] runtime attach failed", error);
  renderRuntime(runtimeSnapshot);
});

