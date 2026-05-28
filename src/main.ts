import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { LogicalSize, getCurrentWindow } from "@tauri-apps/api/window";
import appIconUrl from "./assets/app-icon.png";
import "./styles.css";

type DeviceInfo = {
  id: string;
  name: string;
  platform: string;
  address: string;
  port: number;
  last_seen_ms: number;
  crypto_public_key: string;
};

type Identity = {
  id: string;
  name: string;
  platform: string;
  port: number;
  crypto_public_key: string;
};

type TransferReceipt = {
  file_name: string;
  target_name: string;
  bytes: number;
};

type TransferEvent = {
  direction: "sent" | "received";
  file_name: string;
  peer_name: string;
  bytes: number;
  saved_path?: string | null;
  timestamp_ms: number;
};

type TransferProgress = {
  transfer_id: string;
  direction: "sent" | "received";
  phase: "started" | "progress" | "finished" | "failed";
  file_name: string;
  peer_name: string;
  bytes_transferred: number;
  total_bytes: number;
  encrypted: boolean;
  error?: string | null;
  speed_mbps: number;
  eta_seconds: number;
};

const DEFAULT_TARGET_KEY = "file-sharer.default-target";
const PROTOCOL = "file-sharer.v2";
const CRYPTO_MODE = "dh-sha256-stream-v1";
const DH_PRIME = (1n << 127n) - 1n;
const DH_GENERATOR = 5n;
const TRANSFER_CONTEXT = "file-sharer-transfer-v2";
const CIPHER_CONTEXT = "file-sharer-cipher-v2";
const MAC_CONTEXT = "file-sharer-mac-v2";
const isTauriRuntime = typeof window.__TAURI_INTERNALS__ !== "undefined";
const isMobileRuntime = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
const currentWindowLabel = window.__TAURI_INTERNALS__?.metadata?.currentWindow?.label ?? "main";
const isOverlayWindow =
  currentWindowLabel === "overlay"
  || new URLSearchParams(window.location.search).get("window") === "overlay";
const canControlDesktopOverlay = isTauriRuntime && !isMobileRuntime;

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) {
  throw new Error("Missing #app root");
}

type AppView = "send" | "history" | "settings";

let devices: DeviceInfo[] = [];
let identity: Identity | null = null;
let selectedTargetId = localStorage.getItem(DEFAULT_TARGET_KEY) ?? "";
let isDropActive = false;
let statusText = "等待发现局域网设备";
let transferHistory: TransferEvent[] = [];
let activeTransfers: TransferProgress[] = [];
const progressClearTimers = new Map<string, number>();
type OverlayMode = "normal" | "drag" | "transfer" | "confirm";

let overlayMode: OverlayMode = "normal";
const sendQueue: string[][] = [];
let isSendingQueue = false;
let activeView: AppView = "send";
let receiveDirText = "下载/File Sharer";
let dragSendImmediately = true;
let lanDiscoveryEnabled = true;
let pendingSendPaths: string[] = [];
let lastHandledDropSignature = "";
let lastHandledDropAt = 0;
let confirmRefreshTimer: number | null = null;
let lastOverlaySizeKey = "";
let shouldRepositionConfirmOverlay = false;
let lastDevicesRenderSignature = "";
let lastConfirmRenderSignature = "";
let lastConfirmFilesSignature = "";
let lastConfirmTargetSignature = "";
let lastSendTargetSelectSignature = "";
let lastSettingsTargetSelectSignature = "";
let confirmExpandTimer: number | null = null;

app.innerHTML = `
  <section class="app-shell" id="main-shell">
    <aside class="side-nav" aria-label="主导航">
      <div class="side-brand">
        <img class="brand-logo" src="${appIconUrl}" alt="" aria-hidden="true" />
        <span>
          <strong>File Sharer</strong>
          <small id="self-device">启动中</small>
        </span>
      </div>
      <nav class="nav-list">
        <button class="nav-item active" type="button" data-view="send">发送</button>
        <button class="nav-item" type="button" data-view="history">记录</button>
        <button class="nav-item" type="button" data-view="settings">设置</button>
      </nav>
      <p class="side-status" id="status"></p>
    </aside>

    <main class="workspace">
      <header class="workspace-head">
        <div>
          <p class="eyebrow" id="view-kicker">局域网文件分享</p>
          <h1 id="view-title">发送文件</h1>
        </div>
        <div class="head-actions">
          <button class="icon-button" id="open-dir" type="button" title="打开下载目录">⌘</button>
          <button class="icon-button" id="clear-history" type="button" title="清空记录">⌫</button>
        </div>
      </header>

      <section class="view-panel active" id="send-view">
        <section class="drop-zone" id="drop-zone" aria-label="拖拽文件发送">
          <input id="file-input" class="file-input" type="file" multiple />
          <div class="drop-icon" aria-hidden="true">+</div>
          <div>
            <p class="drop-title">拖入文件</p>
            <p class="drop-subtitle">或点击选择文件</p>
          </div>
        </section>

        <section class="target-row">
          <label for="target-select">默认目标</label>
          <select id="target-select"></select>
        </section>

        <section class="devices-head">
          <span>局域网设备</span>
          <button class="icon-button" id="refresh-devices" type="button" title="刷新设备列表">
            <svg class="refresh-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M20 12a8 8 0 0 1-13.7 5.7M4 12A8 8 0 0 1 17.7 6.3" />
              <path d="M7 18H4v3M17 6h3V3" />
            </svg>
          </button>
        </section>
        <section class="devices" id="devices"></section>
        <section class="progress-wrap" id="progress-wrap"></section>
      </section>

      <section class="view-panel" id="history-view">
        <div class="history-head">
          <span>最近传输</span>
          <small id="history-count">0</small>
        </div>
        <section class="history" id="history"></section>
      </section>

      <section class="view-panel" id="settings-view">
        <section class="settings-group">
          <div class="setting-row edit-row">
            <span>
              <strong>设备名称</strong>
              <small>局域网内其他设备看到的名称</small>
            </span>
            <div class="name-row">
              <input id="name-input" type="text" maxlength="32" autocomplete="off" spellcheck="false" />
              <button id="name-save" type="button">保存</button>
            </div>
          </div>
          <div class="setting-row">
            <span>
              <strong>默认发送目标</strong>
              <small id="default-target-label">未选择</small>
            </span>
            <select id="settings-target-select"></select>
          </div>
        </section>

        <section class="settings-group">
          <div class="setting-row">
            <span>
              <strong>接收文件保存位置</strong>
              <small id="receive-dir">下载/File Sharer</small>
            </span>
            <button class="text-button" id="open-dir-secondary" type="button">打开</button>
          </div>
          <div class="setting-row">
            <span>
              <strong>局域网发现</strong>
              <small id="lan-discovery-status">开启中 · 可被发现</small>
            </span>
            <label class="switch">
              <input type="checkbox" id="lan-discovery" checked />
              <span></span>
            </label>
          </div>
          <div class="setting-row desktop-only">
            <span>
              <strong>拖放后立即发送</strong>
              <small>关闭后拖放文件需确认再发送</small>
            </span>
            <label class="switch">
              <input type="checkbox" id="drag-send-immediately" checked />
              <span></span>
            </label>
          </div>
          <div class="setting-row">
            <span>
              <strong>传输记录</strong>
              <small>最多保留 100 条</small>
            </span>
            <button class="text-button danger" id="clear-history-secondary" type="button">清空</button>
          </div>
        </section>
      </section>
    </main>
  </section>

  <section class="modal-overlay" id="modal-overlay" hidden>
    <div class="modal-card">
      <div class="modal-head">
        <strong id="modal-title">确认</strong>
      </div>
      <p class="modal-body" id="modal-body">确定要执行此操作吗？</p>
      <div class="modal-actions">
        <button class="text-button" id="modal-cancel" type="button">取消</button>
        <button class="text-button primary" id="modal-confirm" type="button">确认</button>
      </div>
    </div>
  </section>

  <section class="overlay-shell" id="overlay-shell">
    <section class="drag-mini" id="drag-mini">
      <div class="drag-card">
        <div class="drag-copy">
          <small>发送给</small>
          <strong id="drag-target">未选择目标</strong>
        </div>
        <div class="drag-local">
          <small id="drag-target-meta">等待局域网设备</small>
        </div>
        <span class="drag-hint" id="drag-hint">松开鼠标开始传输</span>
      </div>
    </section>
    <section class="overlay-confirm" id="overlay-confirm">
      <div class="confirm-card">
        <div class="confirm-main">
          <div class="confirm-head">
            <strong>确认发送</strong>
            <small id="confirm-file-count">0 个文件</small>
          </div>
          <div class="confirm-files" id="confirm-files"></div>
        </div>
        <div class="confirm-footer">
          <div class="confirm-target">
            <label for="confirm-target-select">目标设备</label>
            <select id="confirm-target-select"></select>
          </div>
          <div class="confirm-actions">
            <button class="text-button" id="confirm-cancel" type="button">取消</button>
            <button class="text-button primary" id="confirm-send" type="button">发送</button>
          </div>
        </div>
      </div>
    </section>
    <section class="overlay-progress" id="overlay-progress"></section>
  </section>
`;

document.body.classList.toggle("overlay-window", isOverlayWindow);
document.body.classList.toggle("main-window", !isOverlayWindow);

const mainShell = document.querySelector<HTMLElement>("#main-shell")!;
const overlayShell = document.querySelector<HTMLElement>("#overlay-shell")!;
const selfDevice = document.querySelector<HTMLSpanElement>("#self-device")!;
const nameInput = document.querySelector<HTMLInputElement>("#name-input")!;
const nameSave = document.querySelector<HTMLButtonElement>("#name-save")!;
const dropZone = document.querySelector<HTMLDivElement>("#drop-zone")!;
const fileInput = document.querySelector<HTMLInputElement>("#file-input")!;
const targetSelect = document.querySelector<HTMLSelectElement>("#target-select")!;
const settingsTargetSelect = document.querySelector<HTMLSelectElement>("#settings-target-select")!;
const devicesElement = document.querySelector<HTMLElement>("#devices")!;
const dragTarget = document.querySelector<HTMLElement>("#drag-target")!;
const dragTargetMeta = document.querySelector<HTMLElement>("#drag-target-meta")!;
const dragHint = document.querySelector<HTMLElement>("#drag-hint")!;
const progressElement = document.querySelector<HTMLElement>("#progress-wrap")!;
const overlayProgressElement = document.querySelector<HTMLElement>("#overlay-progress")!;
const overlayConfirmElement = document.querySelector<HTMLElement>("#overlay-confirm")!;
const confirmFilesElement = document.querySelector<HTMLElement>("#confirm-files")!;
const confirmFileCountElement = document.querySelector<HTMLElement>("#confirm-file-count")!;
const confirmTargetSelect = document.querySelector<HTMLSelectElement>("#confirm-target-select")!;
const confirmCancelButton = document.querySelector<HTMLButtonElement>("#confirm-cancel")!;
const confirmSendButton = document.querySelector<HTMLButtonElement>("#confirm-send")!;
const confirmHead = document.querySelector<HTMLElement>(".confirm-head")!;
const historyElement = document.querySelector<HTMLElement>("#history")!;
const historyCountElement = document.querySelector<HTMLElement>("#history-count")!;
const statusElement = document.querySelector<HTMLElement>("#status")!;
const viewTitle = document.querySelector<HTMLElement>("#view-title")!;
const viewKicker = document.querySelector<HTMLElement>("#view-kicker")!;
const defaultTargetLabel = document.querySelector<HTMLElement>("#default-target-label")!;
const receiveDirElement = document.querySelector<HTMLElement>("#receive-dir")!;
const dragSendImmediatelyCheckbox = document.querySelector<HTMLInputElement>("#drag-send-immediately")!;
const lanDiscoveryCheckbox = document.querySelector<HTMLInputElement>("#lan-discovery")!;
const lanDiscoveryStatus = document.querySelector<HTMLElement>("#lan-discovery-status")!;
const modalOverlay = document.querySelector<HTMLElement>("#modal-overlay")!;
const modalTitle = document.querySelector<HTMLElement>("#modal-title")!;
const modalBody = document.querySelector<HTMLElement>("#modal-body")!;
const modalCancel = document.querySelector<HTMLButtonElement>("#modal-cancel")!;
const modalConfirm = document.querySelector<HTMLButtonElement>("#modal-confirm")!;
const openDirButtons = [
  document.querySelector<HTMLButtonElement>("#open-dir")!,
  document.querySelector<HTMLButtonElement>("#open-dir-secondary")!,
];
const clearHistoryButtons = [
  document.querySelector<HTMLButtonElement>("#clear-history")!,
  document.querySelector<HTMLButtonElement>("#clear-history-secondary")!,
];
const refreshDevicesButton = document.querySelector<HTMLButtonElement>("#refresh-devices");

function setStatus(text: string) {
  statusText = text;
  if (!isOverlayWindow) {
    statusElement.textContent = statusText;
  }
}

function render() {
  renderWindowMode();
  renderNavigation();
  renderIdentity();
  renderTargets();
  renderDevices();
  renderProgress();
  renderHistory();
  if (pendingSendPaths.length > 0) {
    renderConfirmPanel(false);
  }

  if (!isOverlayWindow) {
    dropZone.classList.toggle("active", isDropActive);
    statusElement.textContent = statusText;
  }
}

function renderWindowMode() {
  const hasActiveTransfer = activeTransfers.length > 0;
  const showConfirm = pendingSendPaths.length > 0;
  const showTransferShell = hasActiveTransfer || overlayMode === "transfer";
  const showDragMini = isDropActive && !showTransferShell && !showConfirm;
  mainShell.hidden = isOverlayWindow;
  overlayShell.hidden = !isOverlayWindow;
  overlayShell.classList.toggle("transfer", showTransferShell);
  overlayShell.classList.toggle("dragging", showDragMini);
  overlayShell.classList.toggle("confirm", showConfirm);
  if (!showConfirm) {
    overlayShell.classList.remove("confirm-enter");
  }
  if (!isOverlayWindow) {
    syncOverlayMode(showConfirm ? "confirm" : showTransferShell ? "transfer" : showDragMini ? "drag" : overlayMode);
  }
  if (isOverlayWindow) {
    const width = showConfirm || showDragMini ? 560 : 456;
    let height = showDragMini ? 300 : 116;
    if (showConfirm) height = 300;
    else if (showTransferShell) height = 128;
    const sizeKey = `${width}x${height}`;
    if (lastOverlaySizeKey !== sizeKey) {
      lastOverlaySizeKey = sizeKey;
      getCurrentWindow()
        .setSize(new LogicalSize(width, height))
        .then(() => {
          if (shouldRepositionConfirmOverlay) {
            shouldRepositionConfirmOverlay = false;
            return tauriInvoke("position_overlay");
          }
        })
        .catch(() => {});
    } else if (shouldRepositionConfirmOverlay) {
      shouldRepositionConfirmOverlay = false;
      tauriInvoke("position_overlay").catch(() => {});
    }
  }
}

function renderNavigation() {
  if (isOverlayWindow) {
    return;
  }

  for (const item of document.querySelectorAll<HTMLButtonElement>(".nav-item")) {
    item.classList.toggle("active", item.dataset.view === activeView);
  }
  for (const panel of document.querySelectorAll<HTMLElement>(".view-panel")) {
    panel.classList.toggle("active", panel.id === `${activeView}-view`);
  }

  const titles: Record<AppView, { title: string; kicker: string }> = {
    send: { title: "发送文件", kicker: "局域网文件分享" },
    history: { title: "传输记录", kicker: "最近 100 条" },
    settings: { title: "设置", kicker: "设备与接收" },
  };
  viewTitle.textContent = titles[activeView].title;
  viewKicker.textContent = titles[activeView].kicker;
}

function renderIdentity() {
  selfDevice.textContent = identity
    ? `${identity.name} · ${identity.platform}`
    : "启动中";
  const target = currentTarget();
  dragTarget.textContent = target ? `${target.name}` : "未选择目标";
  dragTargetMeta.textContent = target
    ? `${target.platform} · ${target.address}`
    : "等待局域网设备";
  dragHint.textContent = dragSendImmediately ? "松开鼠标开始传输" : "松开鼠标添加到待发送";
  if (identity && document.activeElement !== nameInput) {
    nameInput.value = identity.name;
  }
}

function renderTargets() {
  const target = currentTarget();
  defaultTargetLabel.textContent = target
    ? `${target.name} · ${target.platform}`
    : "未选择";
  receiveDirElement.textContent = receiveDirText;
  openDirButtons.forEach((button) => {
    button.title = isMobileRuntime ? "打开下载目录" : "打开接收目录";
  });
  const secondaryOpenButton = document.querySelector<HTMLButtonElement>("#open-dir-secondary");
  if (secondaryOpenButton) {
    secondaryOpenButton.textContent = isMobileRuntime ? "打开下载" : "打开";
  }

  lastSendTargetSelectSignature = renderTargetSelect(
    targetSelect,
    "发送前选择",
    lastSendTargetSelectSignature,
  );
  lastSettingsTargetSelectSignature = renderTargetSelect(
    settingsTargetSelect,
    "最近使用的设备",
    lastSettingsTargetSelectSignature,
  );
}

function renderTargetSelect(select: HTMLSelectElement, placeholderText: string, previousSignature = "") {
  const signature = targetSelectSignature(placeholderText);
  if (signature === previousSignature) {
    return previousSignature;
  }
  select.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = devices.length > 0 ? placeholderText : "未发现设备";
  select.append(placeholder);

  for (const device of devices) {
    const option = document.createElement("option");
    option.value = device.id;
    option.textContent = `${device.name} · ${device.platform}`;
    select.append(option);
  }

  if (selectedTargetId && devices.some((device) => device.id === selectedTargetId)) {
    select.value = selectedTargetId;
  } else {
    select.value = "";
  }
  return signature;
}

function targetSelectSignature(placeholderText: string) {
  return [
    selectedTargetId,
    placeholderText,
    ...devices.map((device) => [
      device.id,
      device.name,
      device.platform,
    ].join("|")),
  ].join("\n");
}

function renderDevices() {
  const signature = deviceListSignature();
  if (signature === lastDevicesRenderSignature) {
    return;
  }
  lastDevicesRenderSignature = signature;
  devicesElement.innerHTML = "";
  if (devices.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "同一局域网内打开 File Sharer 后会显示在这里";
    devicesElement.append(empty);
  } else {
    for (const device of devices) {
      const item = document.createElement("button");
      item.className = device.id === selectedTargetId ? "device selected" : "device";
      item.type = "button";
      item.innerHTML = `
        <span>
          <strong>${escapeHtml(device.name)}</strong>
          <small>${escapeHtml(device.address)}:${device.port}</small>
        </span>
        <em>${escapeHtml(device.platform)}</em>
      `;
      item.addEventListener("click", () => setDefaultTarget(device.id));
      devicesElement.append(item);
    }
  }
}

function deviceListSignature() {
  return [
    selectedTargetId,
    ...devices.map((device) => [
      device.id,
      device.name,
      device.platform,
      device.address,
      device.port,
    ].join("|")),
  ].join("\n");
}

function renderProgress() {
  progressElement.innerHTML = "";
  overlayProgressElement.innerHTML = "";
  progressElement.hidden = activeTransfers.length === 0;
  overlayProgressElement.hidden = activeTransfers.length === 0;
  for (const progress of activeTransfers) {
    const value = progress.total_bytes > 0
      ? Math.min(100, Math.round((progress.bytes_transferred / progress.total_bytes) * 100))
      : 0;
    const direction = progress.direction === "received" ? "接收" : "发送";
    const peer = progress.direction === "received" ? `来自 ${progress.peer_name}` : `到 ${progress.peer_name}`;

    let state = progress.phase === "failed"
      ? "失败"
      : progress.phase === "finished"
        ? "完成"
        : `${value}%`;

    let speedInfo = "";
    if (progress.phase === "progress" && progress.speed_mbps > 0) {
      speedInfo = ` · ${progress.speed_mbps.toFixed(1)} MB/s`;
      if (progress.eta_seconds > 0) {
        speedInfo += ` · 剩余 ${formatEta(progress.eta_seconds)}`;
      }
    }

    const item = document.createElement("section");
    item.className = `progress-item ${progress.direction} ${progress.phase}`;
    item.innerHTML = `
      <div class="progress-row">
        <span>
          <strong>${direction} ${escapeHtml(progress.file_name)}</strong>
          <small>${escapeHtml(peer)} · ${formatBytes(progress.bytes_transferred)} / ${formatBytes(progress.total_bytes)}${speedInfo}</small>
        </span>
        <button class="cancel-transfer" type="button" data-transfer-id="${escapeHtml(progress.transfer_id)}">×</button>
        <em>${escapeHtml(state)}</em>
      </div>
      <div class="progress-track">
        <span style="width: ${value}%"></span>
      </div>
    `;
    progressElement.append(item);
    overlayProgressElement.append(item.cloneNode(true));
  }
  progressElement.querySelectorAll<HTMLButtonElement>(".cancel-transfer").forEach((button) => {
    button.addEventListener("click", () => {
      const transferId = button.dataset.transferId;
      if (transferId) {
        cancelTransfer(transferId);
      }
    });
  });
}

function renderHistory() {
  historyCountElement.textContent = String(transferHistory.length);
  historyElement.innerHTML = "";
  if (transferHistory.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "最近 100 条发送和接收记录会显示在这里";
    historyElement.append(empty);
  } else {
    for (const event of transferHistory.slice(0, 5)) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = `history-item ${event.direction}`;
      item.disabled = !event.saved_path;
      const peerLabel = event.direction === "received" ? "来自" : "发往";
      item.innerHTML = `
        <span class="history-main">
          <strong>${escapeHtml(event.file_name)}</strong>
          <span class="history-details">
            <small>大小 ${formatBytes(event.bytes)}</small>
            <small>${peerLabel} ${escapeHtml(event.peer_name)}</small>
            <small>时间 ${formatTime(event.timestamp_ms)}</small>
          </span>
        </span>
        <em>${event.saved_path ? "开" : event.direction === "received" ? "收" : "发"}</em>
      `;
      if (event.saved_path) {
        item.addEventListener("click", () => openSavedFile(event));
      }
      historyElement.append(item);
    }
  }
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setDefaultTarget(deviceId: string) {
  selectedTargetId = deviceId;
  localStorage.setItem(DEFAULT_TARGET_KEY, deviceId);
  const device = devices.find((item) => item.id === deviceId);
  setStatus(device ? `默认目标：${device.name}` : "默认目标已更新");
  render();
}

async function saveDeviceName() {
  const name = nameInput.value.trim().replace(/\s+/g, " ");
  if (!name) {
    setStatus("设备名称不能为空");
    nameInput.value = identity?.name ?? "";
    return;
  }

  nameSave.disabled = true;
  try {
    identity = await tauriInvoke<Identity>("set_device_name", { name });
    setStatus(`本机名称：${identity.name}`);
    render();
  } catch (error) {
    setStatus(`保存名称失败：${String(error)}`);
    nameInput.value = identity?.name ?? "";
  } finally {
    nameSave.disabled = false;
  }
}

function currentTarget() {
  if (!selectedTargetId && targetSelect.value) {
    selectedTargetId = targetSelect.value;
  }

  if (!selectedTargetId && devices.length === 1) {
    selectedTargetId = devices[0].id;
  }

  return devices.find((device) => device.id === selectedTargetId);
}

async function refreshDevices() {
  return refreshDevicesWithOptions();
}

async function refreshDevicesForConfirm() {
  return refreshDevicesWithOptions({ probe: true, preserveMissingTarget: true, quiet: true });
}

async function refreshDevicesWithOptions(options: { probe?: boolean; preserveMissingTarget?: boolean; quiet?: boolean } = {}) {
  try {
    if (isTauriRuntime && options.probe !== false) {
      await tauriInvoke("probe_discovery");
      await new Promise((resolve) => window.setTimeout(resolve, 180));
    }
    devices = await tauriInvoke<DeviceInfo[]>("list_devices");
    if (selectedTargetId && !devices.some((device) => device.id === selectedTargetId) && !options.preserveMissingTarget) {
      selectedTargetId = "";
      localStorage.removeItem(DEFAULT_TARGET_KEY);
      setStatus("默认目标暂时离线");
    } else if (!selectedTargetId && devices.length === 1) {
      selectedTargetId = devices[0].id;
      localStorage.setItem(DEFAULT_TARGET_KEY, selectedTargetId);
      setStatus(`默认目标：${devices[0].name}`);
    } else if (devices.length > 0 && statusText === "等待发现局域网设备") {
      setStatus("选择目标后即可发送");
    }
    render();
  } catch (error) {
    if (!options.quiet) {
      setStatus(`设备发现失败：${String(error)}`);
    }
  }
}

function startConfirmRefresh() {
  if (!isTauriRuntime || !isOverlayWindow || confirmRefreshTimer !== null) {
    return;
  }
  refreshDevicesForConfirm().catch(() => {});
  confirmRefreshTimer = window.setInterval(() => {
    if (pendingSendPaths.length === 0) {
      stopConfirmRefresh();
      return;
    }
    refreshDevicesForConfirm().catch(() => {});
  }, 1200);
}

function stopConfirmRefresh() {
  if (confirmRefreshTimer !== null) {
    window.clearInterval(confirmRefreshTimer);
    confirmRefreshTimer = null;
  }
}

async function openSavedFile(event: TransferEvent) {
  if (!event.saved_path) {
    return;
  }

  try {
    await tauriInvoke("open_saved_file", {
      path: event.saved_path,
    });
    setStatus(`已打开：${event.file_name}`);
  } catch (error) {
    setStatus(`打开失败：${String(error)}`);
  }
}

async function refreshHistory() {
  try {
    transferHistory = await tauriInvoke<TransferEvent[]>("transfer_history");
    const latest = transferHistory[0];
    if (latest && latest.direction === "received") {
      setStatus(`已收到：${latest.file_name}`);
    }
    render();
  } catch (error) {
    setStatus(`传输记录刷新失败：${String(error)}`);
  }
}

async function refreshReceiveDir() {
  try {
    receiveDirText = await tauriInvoke<string>("receive_dir");
    render();
  } catch {
    receiveDirText = isMobileRuntime ? "Download/File Sharer" : "下载/File Sharer";
  }
}

async function openReceiveDir() {
  await tauriInvoke("open_receive_dir");
  setStatus("已打开接收目录");
}

async function clearTransferHistory() {
  await tauriInvoke("clear_transfer_history");
  transferHistory = [];
  setStatus("传输记录已清空");
  render();
}

function upsertProgress(progress: TransferProgress) {
  const existingTimer = progressClearTimers.get(progress.transfer_id);
  if (existingTimer) {
    window.clearTimeout(existingTimer);
    progressClearTimers.delete(progress.transfer_id);
  }

  const existingIndex = activeTransfers.findIndex((item) => item.transfer_id === progress.transfer_id);
  if (existingIndex >= 0) {
    activeTransfers[existingIndex] = progress;
  } else {
    activeTransfers.unshift(progress);
  }

  activeTransfers = activeTransfers.slice(0, 4);

  if (progress.phase === "started" || progress.phase === "progress") {
    const action = progress.direction === "received" ? "正在接收" : "正在发送";
    const percent = progress.total_bytes > 0
      ? Math.min(100, Math.round((progress.bytes_transferred / progress.total_bytes) * 100))
      : 0;
    setStatus(`${action}：${progress.file_name} ${percent}%`);
  } else if (progress.phase === "failed" && progress.error) {
    setStatus(`传输失败：${progress.error}`);
  } else if (progress.phase === "finished") {
    const action = progress.direction === "received" ? "已接收" : "已发送";
    setStatus(`${action}：${progress.file_name}`);
  }

  if (progress.phase === "finished" || progress.phase === "failed") {
    const timer = window.setTimeout(() => {
      activeTransfers = activeTransfers.filter((item) => item.transfer_id !== progress.transfer_id);
      progressClearTimers.delete(progress.transfer_id);
      render();
      hideOverlaySoon();
    }, 1600);
    progressClearTimers.set(progress.transfer_id, timer);
  }

  render();
}

async function setOverlayBusy(busy: boolean) {
  if (!canControlDesktopOverlay) {
    return;
  }
  await tauriInvoke("set_overlay_busy", { busy });
}

function cancelTransfer(transferId: string) {
  tauriInvoke("cancel_transfer", { transferId }).catch(() => {});
  const progress = activeTransfers.find((item) => item.transfer_id === transferId);
  if (progress) {
    upsertProgress({
      ...progress,
      phase: "failed",
      error: "传输已取消",
    });
  }
}

async function hideOverlaySoon() {
  if (!canControlDesktopOverlay) {
    return;
  }
  window.setTimeout(() => {
    if (activeTransfers.length === 0 && pendingSendPaths.length === 0 && !isDropActive) {
      setOverlayMode("normal").catch(() => {});
      tauriInvoke("hide_overlay").catch(() => {});
    }
  }, 1_600);
}

async function setOverlayMode(mode: OverlayMode) {
  if (!canControlDesktopOverlay || overlayMode === mode) {
    return;
  }
  if (pendingSendPaths.length > 0 && (mode === "normal" || mode === "drag")) {
    return;
  }
  overlayMode = mode;
  await tauriInvoke("set_overlay_mode", { mode });
}

function syncOverlayMode(mode: OverlayMode) {
  if (!canControlDesktopOverlay || overlayMode === mode) {
    return;
  }
  if (pendingSendPaths.length > 0 && (mode === "normal" || mode === "drag")) {
    return;
  }
  overlayMode = mode;
  tauriInvoke("set_overlay_mode", { mode }).catch(() => {});
}

async function sendPaths(paths: string[]) {
  sendQueue.push(paths);
  void drainSendQueue();
}

async function drainSendQueue() {
  if (isSendingQueue) {
    setStatus(`已加入队列：剩余 ${sendQueue.length} 个任务`);
    return;
  }

  isSendingQueue = true;
  await setOverlayBusy(true);
  try {
    while (sendQueue.length > 0) {
      const paths = sendQueue.shift() ?? [];
      await sendPathBatch(paths);
    }
  } finally {
    isSendingQueue = false;
    isDropActive = false;
    render();
    await setOverlayBusy(false);
    hideOverlaySoon();
  }
}

async function sendPathBatch(paths: string[]) {
  const target = currentTarget();
  if (!target) {
    setStatus("先选择一个局域网目标设备");
    isDropActive = false;
    render();
    hideOverlaySoon();
    return;
  }

  isDropActive = false;
  setStatus(`正在发送 ${paths.length} 个文件到 ${target.name}`);
  overlayMode = "transfer";
  await tauriInvoke("set_overlay_mode", { mode: "transfer" });
  try {
    const receipts = await tauriInvoke<TransferReceipt[]>("send_files", {
      paths,
      targetId: target.id,
    });
    const totalBytes = receipts.reduce((sum, receipt) => sum + receipt.bytes, 0);
    setStatus(`已发送 ${receipts.length} 个文件，共 ${formatBytes(totalBytes)}`);
    await refreshHistory();
  } catch (error) {
    setStatus(`发送失败：${String(error)}`);
  }
}

async function sendBrowserFiles(fileList: FileList) {
  const target = currentTarget();
  if (!target) {
    setStatus("先选择一个局域网目标设备");
    fileInput.value = "";
    return;
  }
  if (!identity) {
    setStatus("本机身份尚未初始化");
    fileInput.value = "";
    return;
  }
  if (!target.crypto_public_key) {
    setStatus("目标设备不支持加密传输");
    fileInput.value = "";
    return;
  }

  const files = Array.from(fileList);
  await setOverlayBusy(true);
  try {
    for (const file of files) {
      await sendEncryptedBrowserFile(file, target);
    }
    await refreshHistory();
  } finally {
    fileInput.value = "";
    isDropActive = false;
    render();
    await setOverlayBusy(false);
    hideOverlaySoon();
  }
}

async function sendEncryptedBrowserFile(file: File, target: DeviceInfo) {
  if (!identity) {
    throw new Error("本机身份尚未初始化");
  }

  const transferId = createTransferId(identity.id, target.id, file.name);
  const progressBase = {
    transfer_id: transferId,
    direction: "sent" as const,
    file_name: file.name,
    peer_name: target.name,
    total_bytes: file.size,
    encrypted: true,
    error: null,
    speed_mbps: 0,
    eta_seconds: 0,
  };
  upsertProgress({
    ...progressBase,
    phase: "started",
    bytes_transferred: 0,
  });

  const plaintext = new Uint8Array(await file.arrayBuffer());
  upsertProgress({
    ...progressBase,
    phase: "progress",
    bytes_transferred: 0,
  });

  const session = await createBrowserSenderSession(target.crypto_public_key);
  const mac = await fileMac(session.macKey, file.name, identity.name, transferId, file.size, plaintext);
  applyStreamCipher(plaintext, session.cipherKey, session.nonce);

  await uploadEncryptedFile({
    target,
    file,
    encrypted: plaintext,
    transferId,
    senderPublic: session.senderPublicHeader,
    nonce: bytesToBase64(session.nonce),
    mac,
    onProgress: (bytes) => {
      upsertProgress({
        ...progressBase,
        phase: "progress",
        bytes_transferred: bytes,
      });
    },
  });

  upsertProgress({
    ...progressBase,
    phase: "finished",
    bytes_transferred: file.size,
  });
  await tauriInvoke("record_sent_transfer", {
    fileName: file.name,
    peerName: target.name,
    bytes: file.size,
  });
  setStatus(`已发送：${file.name}`);
}

async function createBrowserSenderSession(receiverPublicHeader: string) {
  const receiverPublic = decodeU128(receiverPublicHeader);
  const privateKey = randomPrivate();
  const senderPublic = modPow(DH_GENERATOR, privateKey);
  const shared = modPow(receiverPublic, privateKey);
  const nonce = randomBytes(16);
  const keys = await deriveTransferKeys(shared, senderPublic, receiverPublic, nonce);
  return {
    senderPublicHeader: encodeU128(senderPublic),
    nonce,
    cipherKey: keys.cipherKey,
    macKey: keys.macKey,
  };
}

async function deriveTransferKeys(
  shared: bigint,
  senderPublic: bigint,
  receiverPublic: bigint,
  nonce: Uint8Array,
) {
  const transferInput = concatBytes(
    textBytes(TRANSFER_CONTEXT),
    u128ToBytes(shared),
    u128ToBytes(senderPublic),
    u128ToBytes(receiverPublic),
  );
  const transferKey = await sha256(transferInput);
  const cipherKey = await sha256(concatBytes(textBytes(CIPHER_CONTEXT), transferKey));
  const macKey = await sha256(concatBytes(textBytes(MAC_CONTEXT), transferKey));
  return { cipherKey, macKey, nonce };
}

async function fileMac(
  macKey: Uint8Array,
  fileName: string,
  senderName: string,
  transferId: string,
  totalBytes: number,
  plaintext: Uint8Array,
) {
  const macKeyBytes = copyBytes(macKey);
  const macData = copyBytes(
    concatBytes(
      textBytes(PROTOCOL),
      textBytes(transferId),
      textBytes(fileName),
      textBytes(senderName),
      u64ToBytes(totalBytes),
      plaintext,
    ),
  );
  const key = await crypto.subtle.importKey(
    "raw",
    macKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, macData);
  return bytesToBase64(new Uint8Array(signature));
}

function uploadEncryptedFile({
  target,
  file,
  encrypted,
  transferId,
  senderPublic,
  nonce,
  mac,
  onProgress,
}: {
  target: DeviceInfo;
  file: File;
  encrypted: Uint8Array;
  transferId: string;
  senderPublic: string;
  nonce: string;
  mac: string;
  onProgress: (bytes: number) => void;
}) {
  if (!identity) {
    return Promise.reject(new Error("本机身份尚未初始化"));
  }
  const senderIdentity = identity;
  const body = new Blob([copyBytes(encrypted)], { type: "application/octet-stream" });

  return new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `http://${target.address}:${target.port}/upload`);
    xhr.setRequestHeader("X-File-Sharer-Protocol", PROTOCOL);
    xhr.setRequestHeader("X-Sender-Id", senderIdentity.id);
    xhr.setRequestHeader("X-Sender-Name", encodeHeaderValue(senderIdentity.name));
    xhr.setRequestHeader("X-File-Name", encodeHeaderValue(file.name));
    xhr.setRequestHeader("X-Transfer-Id", encodeHeaderValue(transferId));
    xhr.setRequestHeader("X-Crypto-Mode", CRYPTO_MODE);
    xhr.setRequestHeader("X-Crypto-Sender-Public", senderPublic);
    xhr.setRequestHeader("X-Crypto-Nonce", nonce);
    xhr.setRequestHeader("X-Crypto-Mac", mac);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(event.loaded);
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
      } else {
        let message = `接收端拒绝：HTTP ${xhr.status}`;
        try {
          const body = JSON.parse(xhr.responseText) as { error?: string };
          if (body.error) {
            message = `接收端拒绝：${body.error}`;
          }
        } catch {
          // Keep the HTTP status message when the response is not JSON.
        }
        reject(new Error(message));
      }
    };
    xhr.onerror = () => reject(new Error("网络发送失败"));
    xhr.ontimeout = () => reject(new Error("网络发送超时"));
    xhr.timeout = 120_000;
    xhr.send(body);
  });
}

function randomPrivate() {
  const bytes = randomBytes(16);
  bytes[0] &= 0x7f;
  return (bytesToU128(bytes) % (DH_PRIME - 3n)) + 2n;
}

function modPow(base: bigint, exponent: bigint) {
  let result = 1n;
  let current = base % DH_PRIME;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = (result * current) % DH_PRIME;
    }
    current = (current * current) % DH_PRIME;
    power >>= 1n;
  }
  return result;
}

function applyStreamCipher(data: Uint8Array, key: Uint8Array, nonce: Uint8Array) {
  let counter = 0;
  let block = new Uint8Array(64);
  let blockIndex = block.length;
  for (let index = 0; index < data.length; index += 1) {
    if (blockIndex >= block.length) {
      block = chacha20Block(key, counter, nonce);
      counter = (counter + 1) >>> 0;
      blockIndex = 0;
    }
    data[index] ^= block[blockIndex];
    blockIndex += 1;
  }
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array) {
  const constants = textBytes("expand 32-byte k");
  const state = new Uint32Array(16);
  state[0] = readU32Le(constants, 0);
  state[1] = readU32Le(constants, 4);
  state[2] = readU32Le(constants, 8);
  state[3] = readU32Le(constants, 12);
  for (let index = 0; index < 8; index += 1) {
    state[4 + index] = readU32Le(key, index * 4);
  }
  state[12] = counter >>> 0;
  state[13] = readU32Le(nonce, 0);
  state[14] = readU32Le(nonce, 4);
  state[15] = readU32Le(nonce, 8);

  const working = new Uint32Array(state);
  for (let round = 0; round < 10; round += 1) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const output = new Uint8Array(64);
  for (let index = 0; index < 16; index += 1) {
    writeU32Le(output, index * 4, (working[index] + state[index]) >>> 0);
  }
  return output;
}

function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 7);
}

function rotateLeft(value: number, bits: number) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function readU32Le(bytes: Uint8Array, offset: number) {
  return (
    bytes[offset]
    | (bytes[offset + 1] << 8)
    | (bytes[offset + 2] << 16)
    | (bytes[offset + 3] << 24)
  ) >>> 0;
}

function writeU32Le(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function encodeU128(value: bigint) {
  return bytesToBase64(u128ToBytes(value));
}

function decodeU128(value: string) {
  const parsed = bytesToU128(base64ToBytes(value));
  if (parsed < 2n || parsed >= DH_PRIME) {
    throw new Error("目标设备加密公钥无效");
  }
  return parsed;
}

function u128ToBytes(value: bigint) {
  const bytes = new Uint8Array(16);
  let current = value;
  for (let index = 15; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
}

function u64ToBytes(value: number) {
  const bytes = new Uint8Array(8);
  let current = BigInt(value);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
}

function bytesToU128(bytes: Uint8Array) {
  if (bytes.length !== 16) {
    throw new Error("加密数据长度无效");
  }
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function sha256(bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copyBytes(bytes)));
}

function textBytes(value: string) {
  return new TextEncoder().encode(value);
}

function concatBytes(...chunks: Uint8Array[]) {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function copyBytes(bytes: Uint8Array) {
  const output = new Uint8Array(bytes.byteLength);
  output.set(bytes);
  return output.buffer;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function createTransferId(senderId: string, targetId: string, fileName: string) {
  const random = crypto.getRandomValues(new Uint32Array(2));
  return `${senderId.slice(0, 8)}-${targetId.slice(0, 8)}-${Date.now().toString(16)}-${random[0].toString(16)}-${hashString(fileName)}`;
}

function hashString(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function encodeHeaderValue(value: string) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function formatTime(timestampMs: number) {
  return new Date(timestampMs).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatEta(seconds: number): string {
  if (seconds < 60) return `${seconds}秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分${seconds % 60}秒`;
  return `${Math.floor(seconds / 3600)}时${Math.floor((seconds % 3600) / 60)}分`;
}

targetSelect.addEventListener("change", () => {
  if (targetSelect.value) {
    setDefaultTarget(targetSelect.value);
  }
});
settingsTargetSelect.addEventListener("change", () => {
  if (settingsTargetSelect.value) {
    setDefaultTarget(settingsTargetSelect.value);
  }
});
confirmTargetSelect.addEventListener("change", () => {
  if (confirmTargetSelect.value) {
    setDefaultTarget(confirmTargetSelect.value);
  }
});

for (const item of document.querySelectorAll<HTMLButtonElement>(".nav-item")) {
  item.addEventListener("click", () => {
    const view = item.dataset.view;
    if (view === "send" || view === "history" || view === "settings") {
      activeView = view;
      render();
    }
  });
}

for (const button of openDirButtons) {
  button.addEventListener("click", () => {
    openReceiveDir().catch((error) => setStatus(`打开目录失败：${String(error)}`));
  });
}

for (const button of clearHistoryButtons) {
  button.addEventListener("click", () => {
    clearTransferHistory().catch((error) => setStatus(`清空记录失败：${String(error)}`));
  });
}

if (refreshDevicesButton) {
  refreshDevicesButton.addEventListener("click", () => {
    refreshDevicesButton.classList.add("spinning");
    const startTime = Date.now();
    refreshDevices().catch(() => {}).finally(() => {
      const elapsed = Date.now() - startTime;
      const minDuration = 500;
      const cleanup = () => {
        refreshDevicesButton.classList.remove("spinning");
      };
      if (elapsed < minDuration) {
        window.setTimeout(cleanup, minDuration - elapsed);
      } else {
        cleanup();
      }
    });
  });
}

if (dragSendImmediatelyCheckbox) {
  dragSendImmediatelyCheckbox.addEventListener("change", () => {
    saveDragSendImmediately(dragSendImmediatelyCheckbox.checked).catch(() => {});
  });
}

if (lanDiscoveryCheckbox) {
  lanDiscoveryCheckbox.addEventListener("change", () => {
    if (!lanDiscoveryCheckbox.checked) {
      // 用户要关闭，显示自定义确认对话框
      showModal({
        title: "关闭局域网发现",
        body: "关闭后，本设备将完全隐身：既不会被其他设备发现，也无法发现其他设备。",
        confirmText: "确认关闭",
        cancelText: "保持开启",
        onConfirm: () => {
          setDiscoveryEnabled(false);
        },
        onCancel: () => {
          // 恢复开关状态
          lanDiscoveryCheckbox.checked = true;
        }
      });
      return;
    }

    // 用户直接开启
    setDiscoveryEnabled(true);
  });
}

function setDiscoveryEnabled(enabled: boolean) {
  lanDiscoveryEnabled = enabled;

  // 更新状态文字
  if (lanDiscoveryStatus) {
    lanDiscoveryStatus.textContent = lanDiscoveryEnabled
      ? "开启中 · 可被发现"
      : "已关闭 · 完全隐身";
  }

  // 保存到 localStorage
  localStorage.setItem("file-sharer.lan-discovery", String(lanDiscoveryEnabled));

  // 通知后端
  if (isTauriRuntime) {
    tauriInvoke("set_discovery_enabled", { enabled })
      .then(() => {
        setStatus(lanDiscoveryEnabled ? "局域网发现已开启" : "局域网发现已关闭");
      })
      .catch(() => {});
  }
}

type ModalOptions = {
  title: string;
  body: string;
  confirmText: string;
  cancelText: string;
  onConfirm: () => void;
  onCancel: () => void;
};

let currentModalResolve: ((value: boolean) => void) | null = null;

function showModal(options: ModalOptions) {
  modalTitle.textContent = options.title;
  modalBody.textContent = options.body;
  modalConfirm.textContent = options.confirmText;
  modalCancel.textContent = options.cancelText;
  modalOverlay.hidden = false;

  const handleConfirm = () => {
    cleanup();
    options.onConfirm();
  };

  const handleCancel = () => {
    cleanup();
    options.onCancel();
  };

  const handleKeydown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      handleCancel();
    }
  };

  const cleanup = () => {
    modalOverlay.hidden = true;
    modalConfirm.removeEventListener("click", handleConfirm);
    modalCancel.removeEventListener("click", handleCancel);
    document.removeEventListener("keydown", handleKeydown);
  };

  modalConfirm.addEventListener("click", handleConfirm);
  modalCancel.addEventListener("click", handleCancel);
  document.addEventListener("keydown", handleKeydown);
}

if (confirmCancelButton) {
  confirmCancelButton.addEventListener("click", async () => {
    pendingSendPaths = [];
    stopConfirmRefresh();
    resetConfirmRenderCache();
    await setOverlayBusy(false).catch(() => {});
    overlayMode = "normal";
    lastOverlaySizeKey = "";
    await tauriInvoke("set_overlay_mode", { mode: "normal" }).catch(() => {});
    renderConfirmPanel();
    render();
    hideOverlaySoon();
  });
}

if (confirmSendButton) {
  confirmSendButton.addEventListener("click", () => {
    if (pendingSendPaths.length === 0) {
      return;
    }
    const targetId = confirmTargetSelect.value;
    if (targetId) {
      selectedTargetId = targetId;
      localStorage.setItem(DEFAULT_TARGET_KEY, targetId);
    }
    const paths = [...pendingSendPaths];
    pendingSendPaths = [];
    stopConfirmRefresh();
    resetConfirmRenderCache();
    overlayMode = "transfer";
    lastOverlaySizeKey = "";
    tauriInvoke("set_overlay_mode", { mode: "transfer" }).catch(() => {});
    renderConfirmPanel();
    render();
    sendPaths(paths);
  });
}

if (confirmHead) {
  confirmHead.addEventListener("pointerdown", (event) => {
    if (isOverlayWindow && event.button === 0) {
      getCurrentWindow().startDragging().catch(() => {});
    }
  });
}

nameSave.addEventListener("click", () => {
  saveDeviceName().catch((error) => setStatus(`保存名称失败：${String(error)}`));
});
nameInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    nameInput.blur();
    saveDeviceName().catch((error) => setStatus(`保存名称失败：${String(error)}`));
  }
});
nameInput.addEventListener("blur", () => {
  if (identity && nameInput.value.trim() !== identity.name) {
    saveDeviceName().catch((error) => setStatus(`保存名称失败：${String(error)}`));
  }
});

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files && fileInput.files.length > 0) {
    sendBrowserFiles(fileInput.files).catch((error) => {
      setStatus(`发送失败：${String(error)}`);
    });
  }
});

dropZone.addEventListener("dragover", (event) => {
  if (isTauriRuntime) {
    return;
  }
  event.preventDefault();
  isDropActive = true;
  setStatus("松开鼠标发送文件");
  render();
});

dropZone.addEventListener("dragleave", () => {
  if (isTauriRuntime) {
    return;
  }
  isDropActive = false;
  render();
});

dropZone.addEventListener("drop", (event) => {
  if (isTauriRuntime) {
    return;
  }
  event.preventDefault();
  isDropActive = false;
  render();

  if (event.dataTransfer?.files && event.dataTransfer.files.length > 0) {
    sendBrowserFiles(event.dataTransfer.files).catch((error) => {
      setStatus(`发送失败：${String(error)}`);
    });
  }
});

async function bindDesktopDrop() {
  if (!isTauriRuntime) {
    return;
  }

  await listen<boolean>("desktop-file-drag", (event) => {
    isDropActive = event.payload;
    if (event.payload) {
      setStatus(dragSendImmediately ? "松开鼠标发送文件" : "松开鼠标添加到待发送");
      overlayMode = pendingSendPaths.length > 0 ? "confirm" : "drag";
    } else {
      if (pendingSendPaths.length > 0) {
        isDropActive = false;
        overlayMode = "confirm";
        render();
        return;
      }
      overlayMode = pendingSendPaths.length > 0 ? "confirm" : "normal";
    }
    render();
  });

  if (isOverlayWindow) {
    await getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type === "over") {
        isDropActive = activeTransfers.length === 0;
        overlayMode = activeTransfers.length > 0
          ? "transfer"
          : pendingSendPaths.length > 0
            ? "confirm"
            : "drag";
        render();
        return;
      }

      if (event.payload.type === "drop") {
        isDropActive = false;
        handleDropPaths(event.payload.paths);
        return;
      }

      isDropActive = false;
      overlayMode = pendingSendPaths.length > 0 ? "confirm" : "normal";
      render();
      hideOverlaySoon();
    });
    return;
  }

  await getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === "over") {
      if (activeTransfers.length > 0 || pendingSendPaths.length > 0) {
        return;
      }
      isDropActive = true;
      setStatus(dragSendImmediately ? "松开鼠标发送文件" : "松开鼠标添加到待发送");
      setOverlayMode("drag")
        .then(() => tauriInvoke("show_overlay"))
        .catch(() => {});
      render();
      return;
    }

    if (event.payload.type === "drop") {
      isDropActive = false;
      handleDropPaths(event.payload.paths);
      return;
    }

    isDropActive = false;
    setStatus("拖拽已取消");
    render();
    hideOverlaySoon();
  });
}

function handleDropPaths(paths: string[]) {
  const normalizedPaths = dedupePaths(paths);
  if (normalizedPaths.length === 0 || isDuplicateDrop(normalizedPaths)) {
    return;
  }

  if (dragSendImmediately) {
    overlayMode = "transfer";
    tauriInvoke("set_overlay_mode", { mode: "transfer" }).catch(() => {});
    sendPaths(normalizedPaths);
  } else {
    const wasConfirming = pendingSendPaths.length > 0;
    pendingSendPaths = dedupePaths([...pendingSendPaths, ...normalizedPaths]);
    isDropActive = false;
    overlayMode = "confirm";
    shouldRepositionConfirmOverlay = !wasConfirming;
    if (!wasConfirming) {
      triggerConfirmExpandAnimation();
    }
    setOverlayBusy(true).catch(() => {});
    if (!wasConfirming) {
      tauriInvoke("set_overlay_mode", { mode: "confirm" }).catch(() => {});
    }
    setStatus(`已添加 ${pendingSendPaths.length} 个待发送文件`);
    renderConfirmPanel();
    startConfirmRefresh();
    render();
  }
}

function triggerConfirmExpandAnimation() {
  if (!isOverlayWindow) {
    return;
  }
  if (confirmExpandTimer !== null) {
    window.clearTimeout(confirmExpandTimer);
  }
  overlayShell.classList.remove("confirm-enter");
  window.requestAnimationFrame(() => {
    overlayShell.classList.add("confirm-enter");
    confirmExpandTimer = window.setTimeout(() => {
      overlayShell.classList.remove("confirm-enter");
      confirmExpandTimer = null;
    }, 260);
  });
}

function dedupePaths(paths: string[]) {
  return [...new Set(paths.filter((path) => path.trim().length > 0))];
}

function isDuplicateDrop(paths: string[]) {
  const signature = [...paths].sort().join("\n");
  const now = Date.now();
  const duplicate = signature === lastHandledDropSignature && now - lastHandledDropAt < 800;
  lastHandledDropSignature = signature;
  lastHandledDropAt = now;
  return duplicate;
}

function renderConfirmPanel(force = true) {
  const signature = confirmPanelSignature();
  if (!force && signature === lastConfirmRenderSignature) {
    return;
  }
  lastConfirmRenderSignature = signature;
  confirmFileCountElement.textContent = `${pendingSendPaths.length} 个文件`;
  renderConfirmFiles(force);
  renderConfirmTarget(force);
}

function renderConfirmFiles(force = true) {
  const filesSignature = pendingSendPaths.join("\n");
  if (!force && filesSignature === lastConfirmFilesSignature) {
    return;
  }
  lastConfirmFilesSignature = filesSignature;
  confirmFilesElement.innerHTML = "";

  for (const path of pendingSendPaths) {
    const fileName = path.split(/[\\/]/).pop() || path;
    const item = document.createElement("div");
    item.className = "confirm-file-item";
    item.innerHTML = `
      <span class="confirm-file-name">${escapeHtml(fileName)}</span>
      <button class="confirm-file-remove" data-path="${escapeHtml(path)}" type="button">×</button>
    `;
    confirmFilesElement.append(item);
  }

  confirmFilesElement.querySelectorAll<HTMLButtonElement>(".confirm-file-remove").forEach((button) => {
    button.addEventListener("click", async () => {
      const path = button.dataset.path;
      if (path) {
        pendingSendPaths = pendingSendPaths.filter((p) => p !== path);
        if (pendingSendPaths.length === 0) {
          stopConfirmRefresh();
          resetConfirmRenderCache();
          await setOverlayBusy(false).catch(() => {});
          overlayMode = "normal";
          lastOverlaySizeKey = "";
          await tauriInvoke("set_overlay_mode", { mode: "normal" }).catch(() => {});
          hideOverlaySoon();
        }
        renderConfirmPanel();
        render();
      }
    });
  });
}

function resetConfirmRenderCache() {
  lastConfirmRenderSignature = "";
  lastConfirmFilesSignature = "";
  lastConfirmTargetSignature = "";
}

function renderConfirmTarget(force = true) {
  const targetSignature = [
    selectedTargetId,
    devices.map((device) => `${device.id}|${device.name}|${device.platform}`).join("\n"),
  ].join("\n---\n");
  if (!force && targetSignature === lastConfirmTargetSignature) {
    return;
  }
  lastConfirmTargetSignature = targetSignature;
  confirmTargetSelect.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = devices.length > 0 ? "选择目标设备" : "未发现设备";
  confirmTargetSelect.append(placeholder);

  for (const device of devices) {
    const option = document.createElement("option");
    option.value = device.id;
    option.textContent = `${device.name} · ${device.platform}`;
    confirmTargetSelect.append(option);
  }

  if (selectedTargetId && devices.some((device) => device.id === selectedTargetId)) {
    confirmTargetSelect.value = selectedTargetId;
  } else {
    confirmTargetSelect.value = "";
  }
}

function confirmPanelSignature() {
  return [
    pendingSendPaths.join("\n"),
    selectedTargetId,
    deviceListSignature(),
  ].join("\n---\n");
}

async function bindTransferProgress() {
  if (!isTauriRuntime) {
    return;
  }

  await listen<TransferProgress>("transfer-progress", (event) => {
    upsertProgress(event.payload);
  });
}

async function bindDeviceEvents() {
  if (!isTauriRuntime) {
    return;
  }

  await listen<DeviceInfo>("device-discovered", (event) => {
    const device = event.payload;
    const existingIndex = devices.findIndex((d) => d.id === device.id);
    if (existingIndex >= 0) {
      devices[existingIndex] = device;
    } else {
      devices.push(device);
      setStatus(`发现设备：${device.name}`);
    }
    devices.sort((a, b) => a.name.localeCompare(b.name));
    if (!selectedTargetId && devices.length === 1) {
      selectedTargetId = devices[0].id;
      localStorage.setItem(DEFAULT_TARGET_KEY, selectedTargetId);
    }
    render();
  });

  await listen<string>("device-lost", (event) => {
    const deviceId = event.payload;
    const index = devices.findIndex((d) => d.id === deviceId);
    if (index >= 0) {
      const lostDevice = devices[index];
      devices.splice(index, 1);
      if (selectedTargetId === deviceId) {
        selectedTargetId = "";
        localStorage.removeItem(DEFAULT_TARGET_KEY);
        setStatus(`默认目标 ${lostDevice.name} 已离线`);
      }
      render();
    }
  });
}

async function boot() {
  try {
    identity = await tauriInvoke<Identity>("device_identity");
    await loadDragSendImmediately();
    await loadLanDiscovery();
    render();
    await refreshDevices();
    await refreshHistory();
    await refreshReceiveDir();
    await bindDesktopDrop();
    await bindTransferProgress();
    await bindDeviceEvents();
    window.setInterval(refreshHistory, 2000);
  } catch (error) {
    setStatus(`启动失败：${String(error)}`);
  }
}

async function loadLanDiscovery() {
  const stored = localStorage.getItem("file-sharer.lan-discovery");
  lanDiscoveryEnabled = stored !== "false";

  // 同步后端状态
  if (isTauriRuntime) {
    try {
      const backendEnabled = await tauriInvoke<boolean>("is_discovery_enabled");
      // 如果 localStorage 和后端不一致，以 localStorage 为准
      if (backendEnabled !== lanDiscoveryEnabled) {
        await tauriInvoke("set_discovery_enabled", { enabled: lanDiscoveryEnabled });
      }
    } catch {
      // 后端可能不支持，忽略错误
    }
  }

  if (lanDiscoveryCheckbox) {
    lanDiscoveryCheckbox.checked = lanDiscoveryEnabled;
  }
  if (lanDiscoveryStatus) {
    lanDiscoveryStatus.textContent = lanDiscoveryEnabled
      ? "开启中 · 可被发现"
      : "已关闭 · 不可被发现";
  }
}

async function loadDragSendImmediately() {
  try {
    const value = await tauriInvoke<boolean>("get_drag_send_immediately");
    dragSendImmediately = value;
    if (dragSendImmediatelyCheckbox) {
      dragSendImmediatelyCheckbox.checked = value;
    }
  } catch {
    // Fallback to localStorage
    const stored = localStorage.getItem("file-sharer.drag-send-immediately");
    dragSendImmediately = stored !== "false";
    if (dragSendImmediatelyCheckbox) {
      dragSendImmediatelyCheckbox.checked = dragSendImmediately;
    }
  }
}

async function saveDragSendImmediately(value: boolean) {
  dragSendImmediately = value;
  localStorage.setItem("file-sharer.drag-send-immediately", String(value));
  try {
    await tauriInvoke("set_drag_send_immediately", { value });
  } catch {
    // Ignore backend save errors
  }
}

boot();

async function tauriInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauriRuntime) {
    return invoke<T>(command, args);
  }

  if (command === "device_identity") {
    return {
      id: "browser-preview",
      name: "Browser Preview",
      platform: "web",
      port: 45892,
      crypto_public_key: "",
    } as T;
  }

  if (command === "list_devices") {
    return [] as T;
  }

  if (command === "transfer_history") {
    return [] as T;
  }

  if (command === "record_sent_transfer") {
    return undefined as T;
  }

  if (command === "clear_transfer_history") {
    return undefined as T;
  }

  if (command === "receive_dir") {
    return (isMobileRuntime ? "Download/File Sharer" : "下载/File Sharer") as T;
  }

  if (command === "set_device_name") {
    const name = String(args?.name ?? "").trim() || "Browser Preview";
    return {
      id: "browser-preview",
      name,
      platform: "web",
      port: 45892,
      crypto_public_key: "",
    } as T;
  }

  if (
    command === "set_overlay_busy"
    || command === "set_overlay_mode"
    || command === "position_overlay"
    || command === "show_overlay"
    || command === "hide_overlay"
    || command === "open_receive_dir"
  ) {
    return undefined as T;
  }

  if (command === "get_drag_send_immediately") {
    const stored = localStorage.getItem("file-sharer.drag-send-immediately");
    return (stored !== "false") as T;
  }

  if (command === "set_drag_send_immediately") {
    localStorage.setItem("file-sharer.drag-send-immediately", String(args?.value ?? true));
    return undefined as T;
  }

  throw new Error("当前预览环境不能访问桌面文件路径");
}
