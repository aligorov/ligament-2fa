// twofa: консоль удаленной поддержки (SOS) и WebRTC просмотрщик экрана.
// Полностью соответствует Content-Security-Policy (без inline-скриптов и inline-обработчиков).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ----------------------------------------------------
  // СЕКЦИЯ 1: ОЧЕРЕДЬ ЗАЯВОК SOS (/admin/support)
  // ----------------------------------------------------
  const supportListEl = document.querySelector(".support-list");
  const btnToggleSound = document.getElementById("btn-toggle-sound");
  const btnOpenSupportSettings = document.getElementById("btn-open-support-settings");
  const btnCloseSupportSettings = document.getElementById("btn-close-support-settings");
  const btnCancelSupportSettings = document.getElementById("btn-cancel-support-settings");
  const supportSettingsModal = document.getElementById("support-settings-modal");
  const btnAddCategoryRow = document.getElementById("btn-add-category-row");
  const categoriesTbody = document.getElementById("categories-tbody");

  function playSosChime() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
      osc.frequency.setValueAtTime(880.0, ctx.currentTime + 0.12); // A5
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.38);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.38);
    } catch (_) {}
  }

  if (btnToggleSound) {
    const isSoundEnabled = localStorage.getItem("support_sound_enabled") === "1";
    btnToggleSound.textContent = isSoundEnabled ? "🔔 Звук: Вкл" : "🔔 Звук: Выкл";
    if (isSoundEnabled) btnToggleSound.classList.add("primary");

    btnToggleSound.addEventListener("click", () => {
      const current = localStorage.getItem("support_sound_enabled") === "1";
      const next = !current;
      localStorage.setItem("support_sound_enabled", next ? "1" : "0");
      btnToggleSound.textContent = next ? "🔔 Звук: Вкл" : "🔔 Звук: Выкл";
      btnToggleSound.classList.toggle("primary", next);
      if (next) {
        playSosChime();
      }
    });
  }

  // Проверка появления новых обращений в очереди для воспроизведения сигнала
  if (supportListEl) {
    const curWaiting = parseInt(supportListEl.dataset.waitingCount, 10) || 0;
    const prevWaitingStr = sessionStorage.getItem("support_prev_waiting");
    if (prevWaitingStr !== null) {
      const prevWaiting = parseInt(prevWaitingStr, 10) || 0;
      if (curWaiting > prevWaiting && localStorage.getItem("support_sound_enabled") === "1") {
        playSosChime();
      }
    }
    sessionStorage.setItem("support_prev_waiting", String(curWaiting));
  }

  // Модальное окно настроек категорий и порогов
  if (btnOpenSupportSettings && supportSettingsModal) {
    btnOpenSupportSettings.addEventListener("click", () => {
      supportSettingsModal.classList.add("visible");
    });
  }

  function closeSupportSettings() {
    if (supportSettingsModal) {
      supportSettingsModal.classList.remove("visible");
    }
  }

  if (btnCloseSupportSettings) btnCloseSupportSettings.addEventListener("click", closeSupportSettings);
  if (btnCancelSupportSettings) btnCancelSupportSettings.addEventListener("click", closeSupportSettings);

  if (supportSettingsModal) {
    supportSettingsModal.addEventListener("click", (e) => {
      if (e.target === supportSettingsModal) {
        closeSupportSettings();
      }
    });
  }

  const supportSettingsForm = supportSettingsModal ? supportSettingsModal.querySelector("form") : null;
  if (supportSettingsForm) {
    supportSettingsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = supportSettingsForm.querySelector("button[type='submit']");
      const origText = submitBtn ? submitBtn.innerHTML : "💾 Сохранить настройки";
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = "⏳ Сохранение...";
      }

      try {
        const formData = new FormData(supportSettingsForm);
        const params = new URLSearchParams(formData);
        const csrfToken = formData.get("csrf_token");
        const headers = {
          "Accept": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        };
        if (csrfToken) {
          headers["X-CSRF-Token"] = csrfToken;
        }

        const res = await fetch("/admin/support", {
          method: "POST",
          headers: headers,
          body: params
        });

        if (res.ok) {
          if (submitBtn) {
            submitBtn.innerHTML = "✅ Сохранено!";
            submitBtn.classList.remove("primary");
            submitBtn.classList.add("ok");
          }
          setTimeout(() => {
            closeSupportSettings();
            location.reload();
          }, 500);
        } else {
          let errMsg = "Ошибка сохранения настроек";
          try {
            const data = await res.json();
            if (data && data.error) errMsg = data.error;
          } catch (_) {}
          alert(errMsg);
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = origText;
          }
        }
      } catch (err) {
        alert("Ошибка сети при сохранении: " + err.message);
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = origText;
        }
      }
    });
  }

  if (btnAddCategoryRow && categoriesTbody) {
    btnAddCategoryRow.addEventListener("click", () => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><input type="text" name="cat_id[]" class="input sm mono cat-input-field" required placeholder="it"></td>
        <td><input type="text" name="cat_title[]" class="input sm cat-input-field" required placeholder="Новая служба"></td>
        <td class="td-icon-center"><input type="text" name="cat_icon[]" class="input sm cat-input-field cat-icon-input" value="🛟"></td>
        <td><input type="text" name="cat_emails[]" class="input sm cat-input-field" placeholder="support@corp.ru"></td>
        <td><input type="text" name="cat_telegram[]" class="input sm mono cat-input-field" placeholder="-100..."></td>
        <td class="td-del-center"><button type="button" class="btn ghost sm danger cat-row-del" title="Удалить">✕</button></td>
      `;
      categoriesTbody.appendChild(tr);
      const firstInp = tr.querySelector("input");
      if (firstInp) firstInp.focus();
    });
  }

  document.addEventListener("click", (e) => {
    if (e.target && e.target.classList.contains("cat-row-del")) {
      const row = e.target.closest("tr");
      if (row) row.remove();
    }
  });

  // ----------------------------------------------------
  // СЕКЦИЯ 2: КОНСОЛЬ УДАЛЕННОГО ДОСТУПА (/admin/support/{id}/viewer)
  // ----------------------------------------------------
  const viewerEl = document.getElementById("support-viewer");
  if (!viewerEl) return;

  const sessionID = viewerEl.dataset.sessionId;
  const wsEndpoint = viewerEl.dataset.wsEndpoint;
  const transferToken = viewerEl.dataset.transferToken || "";
  const operatorName = viewerEl.dataset.operatorName || "Инженер поддержки";
  const accessMode = viewerEl.dataset.accessMode || "full_control";

  let ws = null;
  let peerConnection = null;
  let inputChannel = null;
  let isControlEnabled = false;
  let isClientInputBlocked = false;
  let currentZoom = 1.0;
  let isScaleFit = true;

  const statusBadge = document.getElementById("session-status-badge");
  const numberMatchCard = document.getElementById("number-match-card");
  const numberMatchDigits = document.getElementById("number-match-digits");
  const connectionStatusText = document.getElementById("connection-status-text");
  const videoPlaceholder = document.getElementById("video-placeholder");
  const remoteVideo = document.getElementById("remote-video");
  const btnToggleControl = document.getElementById("btn-toggle-control");
  const btnFullscreen = document.getElementById("btn-fullscreen");
  const hudEl = document.getElementById("support-hud");
  const btnHudPin = document.getElementById("btn-hud-pin");
  const btnProblemToggle = document.getElementById("btn-problem-toggle");
  const hudProblemPopover = document.getElementById("hud-problem-popover");

  const transferModal = document.getElementById("transfer-modal");
  const transferUserSelect = document.getElementById("transfer-user-select");
  const transferLinkInput = document.getElementById("transfer-link-input");

  const viewerScreenPills = document.getElementById("viewer-screen-pills");
  const viewerScreenSelect = document.getElementById("viewer-screen-select");
  const btnScaleFit = document.getElementById("btn-scale-fit");
  const btnScaleOrig = document.getElementById("btn-scale-orig");
  const btnScaleIn = document.getElementById("btn-scale-in");
  const btnScaleOut = document.getElementById("btn-scale-out");
  const viewerHotkeySelect = document.getElementById("viewer-hotkey-select");
  const btnBlockInput = document.getElementById("btn-block-input");
  const btnClipboardToggle = document.getElementById("btn-clipboard-toggle");
  const clipboardDrawer = document.getElementById("viewer-clipboard-drawer");
  const btnClipboardClose = document.getElementById("btn-clipboard-close");
  const clipboardSendText = document.getElementById("clipboard-send-text");
  const btnClipboardSend = document.getElementById("btn-clipboard-send");
  const btnClipboardRead = document.getElementById("btn-clipboard-read");
  const clipboardReadResult = document.getElementById("clipboard-read-result");
  const clipboardReadVal = document.getElementById("clipboard-read-val");
  const telCpuBadge = document.getElementById("tel-cpu-badge");
  const telDiskBadge = document.getElementById("tel-disk-badge");

  // Чат и Передача файлов
  const btnChatToggle = document.getElementById("btn-chat-toggle");
  const chatBadge = document.getElementById("chat-badge");
  const btnFilesToggle = document.getElementById("btn-files-toggle");
  const viewerChatDrawer = document.getElementById("viewer-chat-drawer");
  const btnChatClose = document.getElementById("btn-chat-close");
  const chatMessagesContainer = document.getElementById("chat-messages-container");
  const chatInputText = document.getElementById("chat-input-text");
  const btnChatSend = document.getElementById("btn-chat-send");
  const chatTemplateChips = document.querySelectorAll(".chat-template-chip");

  const viewerFilesDrawer = document.getElementById("viewer-files-drawer");
  const btnFilesClose = document.getElementById("btn-files-close");
  const filesDropzone = document.getElementById("files-dropzone");
  const fileUploadInput = document.getElementById("file-upload-input");
  const btnSelectFile = document.getElementById("btn-select-file");
  const filesTransferList = document.getElementById("files-transfer-list");
  const canvasDropOverlay = document.getElementById("canvas-drop-overlay");
  const viewerScreenContainer = document.getElementById("viewer-screen-container");

  let unreadChatCount = 0;
  const incomingDownloads = new Map();
  // Собранные, но еще не скачанные оператором файлы: transferId -> { url, filename }
  const pendingIncomingFiles = new Map();

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatBytes(bytes) {
    if (bytes === undefined || bytes === null || isNaN(bytes)) return "0 Б";
    if (bytes < 1024) return bytes + " Б";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " КБ";
    return (bytes / 1048576).toFixed(1) + " МБ";
  }

  function tokenQuery() {
    return transferToken ? "?token=" + encodeURIComponent(transferToken) : "";
  }

  function showNumberMatch(num) {
    if (!num) return;
    if (numberMatchCard) {
      numberMatchCard.classList.remove("hidden");
      numberMatchCard.classList.add("visible");
    }
    if (numberMatchDigits) {
      numberMatchDigits.textContent = num;
    }
    if (connectionStatusText) {
      connectionStatusText.textContent = "Ожидание подтверждения контрольного числа 2FA...";
    }
  }

  function hideNumberMatch() {
    if (numberMatchCard) {
      numberMatchCard.classList.remove("visible");
      numberMatchCard.classList.add("hidden");
    }
  }

  async function startConnectFlow() {
    if (connectionStatusText) {
      connectionStatusText.textContent = "Запрос 2FA подтверждения...";
    }

    try {
      const url = "/api/v1/admin/support/sessions/" + sessionID + "/connect" + tokenQuery();
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ admin_name: operatorName })
      });

      if (!res.ok) {
        let errCode = "HTTP " + res.status;
        try {
          const errData = await res.json();
          if (errData && errData.error) errCode = errData.error;
        } catch (_) {}
        throw new Error(errCode);
      }

      const data = await res.json();
      if (data && data.number_match) {
        showNumberMatch(data.number_match);
      }
    } catch (err) {
      console.error("Connect flow error:", err);
      if (connectionStatusText) {
        connectionStatusText.textContent = "Ошибка подключения: " + err.message;
      }
    }

    createPeerConnection();
  }

  function sendSignal(signal) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(signal));
    } else {
      const url = "/api/v1/admin/support/sessions/" + sessionID + "/signal" + tokenQuery();
      fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signal)
      }).catch((e) => console.error("Signal fallback error:", e));
    }
  }

  function createPeerConnection() {
    if (peerConnection) return;

    const config = {
      iceServers: [
        { urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302", "stun:stun2.l.google.com:19302"] },
        { urls: ["stun:stun.cloudflare.com:3478"] }
      ]
    };

    peerConnection = new RTCPeerConnection(config);

    peerConnection.onconnectionstatechange = () => {
      console.log("Support WebRTC: Connection state ->", peerConnection.connectionState);
      if (peerConnection.connectionState === "connected") {
        if (statusBadge) statusBadge.textContent = "🟢 Подключено (P2P)";
      } else if (peerConnection.connectionState === "failed" || peerConnection.connectionState === "disconnected") {
        if (statusBadge) statusBadge.textContent = "🔴 Связь потеряна";
      }
    };

    peerConnection.ontrack = (event) => {
      console.log("Support WebRTC: Remote track received", event);
      const track = event.track;

      function onStreamReady() {
        if (videoPlaceholder) {
          videoPlaceholder.classList.add("hidden");
        }
        hideNumberMatch();
        if (statusBadge) {
          statusBadge.textContent = "🟢 Активно";
        }
      }

      if (track) {
        track.onunmute = () => {
          console.log("Support WebRTC: Track unmuted");
          onStreamReady();
        };
      }

      if (remoteVideo) {
        if (event.streams && event.streams[0]) {
          remoteVideo.srcObject = event.streams[0];
        } else if (track) {
          remoteVideo.srcObject = new MediaStream([track]);
        }
        remoteVideo.muted = true;
        remoteVideo.playsInline = true;
        remoteVideo.onloadeddata = () => {
          console.log("Support WebRTC: First video frame rendered");
          onStreamReady();
        };
        const playPromise = remoteVideo.play();
        if (playPromise !== undefined) {
          playPromise.then(onStreamReady).catch((e) => console.warn("Video play notice:", e));
        }
      }

      onStreamReady();
    };

    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        sendSignal({ candidate: event.candidate });
      }
    };

    peerConnection.ondatachannel = (event) => {
      attachInputChannel(event.channel);
      console.log("Support WebRTC: Input DataChannel received from client");
    };

    try {
      const dc = peerConnection.createDataChannel("input", { ordered: true });
      attachInputChannel(dc);
    } catch (e) {
      console.warn("Support WebRTC: DataChannel creation note:", e);
    }
  }

  function attachInputChannel(ch) {
    if (!ch) return;
    inputChannel = ch;
    ch.onopen = () => console.log("Support WebRTC: Input DataChannel open");
    ch.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleControlMessage(msg);
      } catch (e) {
        console.error("DataChannel parse error:", e);
      }
    };
  }

  function handleControlMessage(msg) {
    if (!msg || !msg.type) return;

    if (msg.type === "screen_list" && msg.screens && Array.isArray(msg.screens)) {
      if (viewerScreenPills) {
        viewerScreenPills.innerHTML = "";
        msg.screens.forEach((scr, idx) => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "hud-pill" + (scr.primary ? " active" : "");
          btn.dataset.screenId = scr.id;
          btn.title = scr.name || `Монитор ${scr.id}`;
          btn.textContent = `🖥 ${idx + 1}`;
          btn.addEventListener("click", () => {
            viewerScreenPills.querySelectorAll(".hud-pill").forEach((p) => p.classList.remove("active"));
            btn.classList.add("active");
            sendControlMessage({ type: "switch_screen", screen_id: scr.id });
            if (viewerScreenSelect) viewerScreenSelect.value = scr.id;
          });
          viewerScreenPills.appendChild(btn);
        });
      }
      if (viewerScreenSelect) {
        viewerScreenSelect.innerHTML = "";
        msg.screens.forEach((scr) => {
          const opt = document.createElement("option");
          opt.value = scr.id;
          opt.textContent = scr.name || `Монитор ${scr.id}`;
          if (scr.primary) opt.selected = true;
          viewerScreenSelect.appendChild(opt);
        });
      }
    } else if (msg.type === "telemetry") {
      if (telCpuBadge && msg.cpu_percent !== undefined) {
        telCpuBadge.textContent = `⚡ CPU: ${msg.cpu_percent}%`;
        if (msg.cpu_warning || msg.cpu_percent >= 90) {
          telCpuBadge.className = "hud-tel-badge danger";
        } else {
          telCpuBadge.className = "hud-tel-badge";
        }
      }
      if (telDiskBadge && msg.disk_free_gb !== undefined) {
        telDiskBadge.textContent = `💾 Диск: ${msg.disk_free_gb} ГБ (${msg.disk_percent}%)`;
        if (msg.disk_warning || msg.disk_free_gb < 10) {
          telDiskBadge.className = "hud-tel-badge danger";
        } else {
          telDiskBadge.className = "hud-tel-badge";
        }
      }
    } else if (msg.type === "clipboard_data") {
      if (clipboardReadVal && clipboardReadResult) {
        clipboardReadVal.textContent = msg.text || "(буфер обмена пуст)";
        clipboardReadResult.style.display = "block";
      }
    } else if (msg.type === "chat_message") {
      appendChatMessage(msg);
      playMessageSound();
      if (!viewerChatDrawer || !viewerChatDrawer.classList.contains("visible")) {
        unreadChatCount++;
        updateChatBadge();
      }
      if ("Notification" in window && Notification.permission === "granted" && document.hidden) {
        try {
          new Notification(msg.sender_name || "Пользователь (SOS Чат)", {
            body: msg.text || "Новое сообщение",
            icon: "/favicon.ico"
          });
        } catch (_) {}
      }
      flashDocumentTitle("💬 Новое сообщение!");
    } else if (msg.type === "file_start") {
      handleIncomingFileStart(msg);
    } else if (msg.type === "file_chunk") {
      handleIncomingFileChunk(msg);
    } else if (msg.type === "file_end") {
      handleIncomingFileEnd(msg);
    }
  }

  function sendControlMessage(obj) {
    const payload = JSON.stringify(obj);
    if (inputChannel && inputChannel.readyState === "open") {
      inputChannel.send(payload);
    } else if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "input_control", data: obj }));
    }
  }

  const pendingCandidates = [];

  async function handleRemoteSDP(sdp) {
    createPeerConnection();
    try {
      await peerConnection.setRemoteDescription(new RTCSessionDescription(sdp));
      if (sdp.type === "offer") {
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        sendSignal({ sdp: answer });
      }
      while (pendingCandidates.length > 0) {
        const c = pendingCandidates.shift();
        try {
          await peerConnection.addIceCandidate(new RTCIceCandidate(c));
        } catch (e) {
          console.warn("Support WebRTC: Queued candidate error:", e);
        }
      }
    } catch (e) {
      console.error("Support WebRTC: SDP error:", e);
    }
  }

  async function handleRemoteCandidate(candidate) {
    if (!peerConnection) createPeerConnection();
    if (!peerConnection.remoteDescription || !peerConnection.remoteDescription.type) {
      pendingCandidates.push(candidate);
      return;
    }
    try {
      await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (e) {
      console.error("Support WebRTC: ICE Candidate error:", e);
    }
  }

  function handleWSMessage(msg) {
    if (!msg || !msg.type) return;

    if (msg.type === "webrtc_signal") {
      const data = msg.data || msg;
      if (data.sdp) {
        handleRemoteSDP(data.sdp);
      } else if (data.candidate) {
        handleRemoteCandidate(data.candidate);
      } else {
        handleControlMessage(data);
      }
    } else if (msg.type === "support_prompt") {
      showNumberMatch(msg.number_match);
    } else if (msg.type === "session_approved") {
      hideNumberMatch();
      if (statusBadge) statusBadge.textContent = "🟢 Подтверждено";
    } else if (msg.type === "session_rejected") {
      alert("Пользователь отклонил запрос на удаленный доступ.");
      location.href = "/admin/support";
    } else if (msg.type === "support_ended") {
      alert("Сеанс удаленной поддержки завершен.");
      location.href = "/admin/support";
    } else if (msg.type === "input_control" && msg.data) {
      handleControlMessage(msg.data);
    } else {
      handleControlMessage(msg);
    }
  }

  function initWS() {
    if (!wsEndpoint) return;
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const wsURL = proto + location.host + wsEndpoint;

    try {
      ws = new WebSocket(wsURL);
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleWSMessage(msg);
        } catch (e) {
          console.error("Support WS parse error:", e);
        }
      };
      ws.onerror = (e) => console.warn("Support WS connection error:", e);
      ws.onclose = () => console.log("Support WebSocket closed");
    } catch (e) {
      console.error("Support WS init error:", e);
    }
  }

  function toggleInputControl() {
    isControlEnabled = !isControlEnabled;
    if (!btnToggleControl) return;

    if (isControlEnabled) {
      btnToggleControl.className = "hud-btn hud-btn-control active";
      btnToggleControl.textContent = "✓ Управление активно";
      setupInputCapture();
    } else {
      btnToggleControl.className = "hud-btn hud-btn-control";
      btnToggleControl.textContent = "🎮 Включить управление";
      removeInputCapture();
    }
  }

  // Расчет нормализованных координат с поправкой на letterbox черные полосы
  function calculateVideoCoordinates(e) {
    if (!remoteVideo) return { x: 0, y: 0 };
    const rect = remoteVideo.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return { x: 0, y: 0 };

    const videoW = remoteVideo.videoWidth || 1920;
    const videoH = remoteVideo.videoHeight || 1080;
    const videoAspect = videoW / videoH;
    const containerAspect = rect.width / rect.height;

    let renderW = rect.width;
    let renderH = rect.height;
    let offsetX = 0;
    let offsetY = 0;

    if (isScaleFit) {
      if (containerAspect > videoAspect) {
        renderW = rect.height * videoAspect;
        offsetX = (rect.width - renderW) / 2;
      } else {
        renderH = rect.width / videoAspect;
        offsetY = (rect.height - renderH) / 2;
      }
    }

    const x = Math.max(0, Math.min(1, (e.clientX - rect.left - offsetX) / renderW));
    const y = Math.max(0, Math.min(1, (e.clientY - rect.top - offsetY) / renderH));
    return { x, y };
  }

  function onContextMenu(e) {
    if (isControlEnabled) {
      e.preventDefault();
    }
  }

  function onMouseMove(e) {
    if (!isControlEnabled) return;
    const { x, y } = calculateVideoCoordinates(e);
    sendControlMessage({ type: "mouse_move", action: "mouse_move", x, y });
  }

  function onMouseDown(e) {
    if (!isControlEnabled) return;
    e.preventDefault();
    const { x, y } = calculateVideoCoordinates(e);
    sendControlMessage({ type: "mouse_down", action: "mouse_down", button: e.button, x, y });
  }

  function onMouseUp(e) {
    if (!isControlEnabled) return;
    e.preventDefault();
    const { x, y } = calculateVideoCoordinates(e);
    sendControlMessage({ type: "mouse_up", action: "mouse_up", button: e.button, x, y });
  }

  function onWheel(e) {
    if (!isControlEnabled) return;
    e.preventDefault();
    sendControlMessage({ type: "mouse_wheel", deltaX: e.deltaX, deltaY: e.deltaY });
  }

  function onKeyDown(e) {
    if (!isControlEnabled) return;
    const active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT")) {
      return;
    }
    if (e.key === "Tab" || e.key === "Alt" || e.key === "Meta" || e.key.startsWith("F") || (e.ctrlKey && e.key !== "r")) {
      e.preventDefault();
    }
    sendControlMessage({
      type: "key_down",
      action: "key_down",
      key: e.key,
      code: e.code,
      keyCode: e.keyCode,
      ctrl: e.ctrlKey,
      alt: e.altKey,
      shift: e.shiftKey,
      meta: e.metaKey
    });
  }

  function onKeyUp(e) {
    if (!isControlEnabled) return;
    const active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT")) {
      return;
    }
    sendControlMessage({
      type: "key_up",
      action: "key_up",
      key: e.key,
      code: e.code,
      keyCode: e.keyCode,
      ctrl: e.ctrlKey,
      alt: e.altKey,
      shift: e.shiftKey,
      meta: e.metaKey
    });
  }

  function setupInputCapture() {
    if (!remoteVideo) return;
    remoteVideo.addEventListener("contextmenu", onContextMenu);
    remoteVideo.addEventListener("mousemove", onMouseMove);
    remoteVideo.addEventListener("mousedown", onMouseDown);
    remoteVideo.addEventListener("mouseup", onMouseUp);
    remoteVideo.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
  }

  function removeInputCapture() {
    if (!remoteVideo) return;
    remoteVideo.removeEventListener("contextmenu", onContextMenu);
    remoteVideo.removeEventListener("mousemove", onMouseMove);
    remoteVideo.removeEventListener("mousedown", onMouseDown);
    remoteVideo.removeEventListener("mouseup", onMouseUp);
    remoteVideo.removeEventListener("wheel", onWheel);
    window.removeEventListener("keydown", onKeyDown);
    window.removeEventListener("keyup", onKeyUp);
  }

  // Полноэкранный режим (Fullscreen API)
  function toggleFullscreen() {
    const root = viewerEl || document.documentElement;
    if (!document.fullscreenElement) {
      if (root.requestFullscreen) {
        root.requestFullscreen().catch((err) => console.warn("Fullscreen request error:", err));
      } else if (root.webkitRequestFullscreen) {
        root.webkitRequestFullscreen();
      }
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
    }
  }

  if (btnFullscreen) {
    btnFullscreen.addEventListener("click", toggleFullscreen);

    document.addEventListener("fullscreenchange", () => {
      if (document.fullscreenElement) {
        btnFullscreen.classList.add("active");
        btnFullscreen.title = "Выйти из полноэкранного режима (Esc / F11)";
      } else {
        btnFullscreen.classList.remove("active");
        btnFullscreen.title = "На весь экран (F11)";
      }
    });
  }

  // Поповер проблемы
  if (btnProblemToggle && hudProblemPopover) {
    btnProblemToggle.addEventListener("click", (e) => {
      e.stopPropagation();
      hudProblemPopover.classList.toggle("visible");
    });
    document.addEventListener("click", (e) => {
      if (!hudProblemPopover.contains(e.target) && e.target !== btnProblemToggle) {
        hudProblemPopover.classList.remove("visible");
      }
    });
  }

  // Автоскрытие и закрепление HUD
  let isPinned = true;
  if (btnHudPin && hudEl) {
    btnHudPin.addEventListener("click", () => {
      isPinned = !isPinned;
      btnHudPin.classList.toggle("active", isPinned);
      hudEl.classList.toggle("auto-hide", !isPinned);
    });
  }

  // Масштабирование видео
  if (btnScaleFit && remoteVideo) {
    btnScaleFit.addEventListener("click", () => {
      isScaleFit = true;
      currentZoom = 1.0;
      remoteVideo.style.objectFit = "contain";
      remoteVideo.style.width = "100%";
      remoteVideo.style.height = "100%";
      remoteVideo.style.transform = "none";
      btnScaleFit.classList.add("active");
      if (btnScaleOrig) btnScaleOrig.classList.remove("active");
    });
  }

  if (btnScaleOrig && remoteVideo) {
    btnScaleOrig.addEventListener("click", () => {
      isScaleFit = false;
      currentZoom = 1.0;
      remoteVideo.style.objectFit = "none";
      remoteVideo.style.width = "auto";
      remoteVideo.style.height = "auto";
      remoteVideo.style.transform = "none";
      btnScaleOrig.classList.add("active");
      if (btnScaleFit) btnScaleFit.classList.remove("active");
    });
  }

  if (btnScaleIn && remoteVideo) {
    btnScaleIn.addEventListener("click", () => {
      currentZoom = Math.min(currentZoom + 0.25, 3.0);
      remoteVideo.style.transform = `scale(${currentZoom})`;
    });
  }

  if (btnScaleOut && remoteVideo) {
    btnScaleOut.addEventListener("click", () => {
      currentZoom = Math.max(currentZoom - 0.25, 0.5);
      remoteVideo.style.transform = `scale(${currentZoom})`;
    });
  }

  // Горячие клавиши (кнопки)
  for (const btn of document.querySelectorAll(".hud-hotkey-btn")) {
    btn.addEventListener("click", () => {
      const hk = btn.dataset.hotkey;
      if (hk) {
        sendControlMessage({ type: "hotkey", key: hk });
      }
    });
  }

  if (viewerHotkeySelect) {
    viewerHotkeySelect.addEventListener("change", () => {
      const hotkey = viewerHotkeySelect.value;
      if (!hotkey) return;
      sendControlMessage({ type: "hotkey", key: hotkey });
      viewerHotkeySelect.value = "";
    });
  }

  // Блокировка клавиатуры и мыши клиента
  function toggleBlockInput() {
    if (!btnBlockInput) return;
    isClientInputBlocked = !isClientInputBlocked;
    sendControlMessage({ type: "block_input", enabled: isClientInputBlocked });
    if (isClientInputBlocked) {
      btnBlockInput.classList.add("active");
      btnBlockInput.textContent = "🔓 Разблок ввода клиента";
    } else {
      btnBlockInput.classList.remove("active");
      btnBlockInput.textContent = "🔒 Блок ввода клиента";
    }
  }

  if (btnBlockInput) {
    btnBlockInput.addEventListener("click", toggleBlockInput);
  }

  // Глобальные горячие клавиши просмотрщика
  window.addEventListener("keydown", (e) => {
    // F11: Полноэкранный режим
    if (e.key === "F11") {
      e.preventDefault();
      toggleFullscreen();
      return;
    }
    // Ctrl+Alt+C: Открыть/закрыть чат
    if (e.ctrlKey && e.altKey && (e.key === "c" || e.key === "C" || e.code === "KeyC")) {
      e.preventDefault();
      toggleChatDrawer();
      return;
    }
    // Ctrl+Alt+L: Блокировка/разблокировка ввода клиента
    if (e.ctrlKey && e.altKey && (e.key === "l" || e.key === "L" || e.code === "KeyL")) {
      e.preventDefault();
      toggleBlockInput();
      return;
    }
    // Escape: выход из полноэкранного режима или снятие фокуса
    if (e.key === "Escape") {
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else if (document.activeElement === viewerScreenContainer) {
        viewerScreenContainer.blur();
      }
    }
  });

  // Буфер обмена
  if (btnClipboardToggle && clipboardDrawer) {
    btnClipboardToggle.addEventListener("click", () => {
      clipboardDrawer.classList.toggle("visible");
    });
  }

  if (btnClipboardClose && clipboardDrawer) {
    btnClipboardClose.addEventListener("click", () => {
      clipboardDrawer.classList.remove("visible");
    });
  }

  if (btnClipboardSend && clipboardSendText) {
    btnClipboardSend.addEventListener("click", () => {
      const text = clipboardSendText.value;
      if (!text) return;
      sendControlMessage({ type: "clipboard_set", text: text });
      alert("Текст отправлен в буфер обмена клиента.");
    });
  }

  if (btnClipboardRead) {
    btnClipboardRead.addEventListener("click", () => {
      sendControlMessage({ type: "clipboard_get" });
    });
  }

  // ----------------------------------------------------
  // ЧАТ С ПОЛЬЗОВАТЕЛЕМ
  // ----------------------------------------------------
  function playMessageSound() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      if (ctx.state === "suspended") {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
      osc.frequency.setValueAtTime(880.0, ctx.currentTime + 0.1); // A5
      gain.gain.setValueAtTime(0.18, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.32);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.32);
    } catch (_) {}
  }

  let titleFlashTimer = null;
  const originalDocTitle = document.title;
  function flashDocumentTitle(text) {
    if (!document.hidden) return;
    if (titleFlashTimer) clearInterval(titleFlashTimer);
    let state = false;
    titleFlashTimer = setInterval(() => {
      document.title = state ? text : originalDocTitle;
      state = !state;
    }, 1000);
  }
  window.addEventListener("focus", () => {
    if (titleFlashTimer) {
      clearInterval(titleFlashTimer);
      titleFlashTimer = null;
      document.title = originalDocTitle;
    }
  });

  function updateChatBadge() {
    if (!chatBadge) return;
    if (unreadChatCount > 0) {
      chatBadge.textContent = String(unreadChatCount);
      chatBadge.style.display = "inline-flex";
    } else {
      chatBadge.style.display = "none";
    }
  }

  function toggleChatDrawer(force) {
    if (!viewerChatDrawer) return;
    const isOpening = force !== undefined ? force : !viewerChatDrawer.classList.contains("visible");
    if (isOpening) {
      viewerChatDrawer.classList.add("visible");
      if (viewerFilesDrawer) viewerFilesDrawer.classList.remove("visible");
      unreadChatCount = 0;
      updateChatBadge();
      loadChatHistory();
      if (chatInputText) chatInputText.focus();
    } else {
      viewerChatDrawer.classList.remove("visible");
    }
  }

  function appendChatMessage(msg) {
    if (!chatMessagesContainer) return;
    if (msg.id && chatMessagesContainer.querySelector(`[data-msg-id="${msg.id}"]`)) {
      return;
    }
    const emptyHint = chatMessagesContainer.querySelector(".chat-empty-hint");
    if (emptyHint) emptyHint.remove();

    const isOperator = msg.sender === "operator";
    const el = document.createElement("div");
    if (msg.id) el.dataset.msgId = String(msg.id);
    el.className = "chat-msg " + (isOperator ? "chat-msg-out" : "chat-msg-in");

    const timeDate = msg.timestamp ? new Date(msg.timestamp) : new Date();
    const timeStr = timeDate.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const senderDisplay = msg.sender_name || (isOperator ? (operatorName || "Инженер") : "Пользователь");

    el.innerHTML = `
      <div class="chat-msg-meta">
        <strong>${escapeHtml(senderDisplay)}</strong>
        <span>${timeStr}</span>
      </div>
      <div class="chat-msg-text">${escapeHtml(msg.text || "")}</div>
    `;

    chatMessagesContainer.appendChild(el);
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
  }

  async function loadChatHistory() {
    if (!sessionID || !chatMessagesContainer) return;
    try {
      const q = transferToken ? `?token=${encodeURIComponent(transferToken)}` : "";
      const res = await fetch(`/api/v1/support/sessions/${sessionID}/messages${q}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data && Array.isArray(data.messages)) {
        data.messages.forEach((m) => {
          appendChatMessage({
            id: m.id,
            sender: m.sender,
            sender_name: m.sender_name,
            text: m.text,
            timestamp: new Date(m.created_at).getTime()
          });
        });
      }
    } catch (_) {}
  }

  function sendChatMessage(text) {
    if (!text || !text.trim()) return;
    const msgId = "msg_" + Date.now();
    const msg = {
      type: "chat_message",
      id: msgId,
      sender: "operator",
      sender_name: operatorName || "Инженер",
      text: text.trim(),
      timestamp: Date.now()
    };
    sendControlMessage(msg);
    appendChatMessage(msg);
    if (chatInputText) chatInputText.value = "";
    if (sessionID) {
      const q = transferToken ? `?token=${encodeURIComponent(transferToken)}` : "";
      fetch(`/api/v1/support/sessions/${sessionID}/messages${q}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text.trim(), sender_name: operatorName || "Инженер" })
      }).catch(() => {});
    }
  }

  // Загружаем начальную историю сообщений сессии
  loadChatHistory();

  if (btnChatToggle) {
    btnChatToggle.addEventListener("click", () => toggleChatDrawer());
  }
  if (btnChatClose) {
    btnChatClose.addEventListener("click", () => toggleChatDrawer(false));
  }
  if (btnChatSend && chatInputText) {
    btnChatSend.addEventListener("click", () => sendChatMessage(chatInputText.value));
    chatInputText.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage(chatInputText.value);
      }
    });
  }
  chatTemplateChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      if (chatInputText) {
        chatInputText.value = chip.dataset.template || "";
        chatInputText.focus();
      }
    });
  });

  // ----------------------------------------------------
  // ПЕРЕДАЧА ФАЙЛОВ
  // ----------------------------------------------------
  const FILE_CHUNK_SIZE = 32768; // 32KB

  function toggleFilesDrawer(force) {
    if (!viewerFilesDrawer) return;
    const isOpening = force !== undefined ? force : !viewerFilesDrawer.classList.contains("visible");
    if (isOpening) {
      viewerFilesDrawer.classList.add("visible");
      if (viewerChatDrawer) viewerChatDrawer.classList.remove("visible");
    } else {
      viewerFilesDrawer.classList.remove("visible");
    }
  }

  function createTransferUI(transferId, filename, size, direction) {
    if (!filesTransferList) return;
    const emptyHint = filesTransferList.querySelector(".files-empty-hint");
    if (emptyHint) emptyHint.remove();

    const item = document.createElement("div");
    item.className = "file-transfer-item";
    item.id = "transfer-" + transferId;

    const dirIcon = direction === "download" ? "📥" : "📤";
    const dirText = direction === "download" ? "Прием от клиента" : "Отправка на ПК";

    item.innerHTML = `
      <div class="file-transfer-header">
        <span class="file-transfer-name" title="${escapeHtml(filename)}">${dirIcon} ${escapeHtml(filename)}</span>
        <span class="file-transfer-size">${formatBytes(size)}</span>
      </div>
      <div class="file-transfer-bar-wrap">
        <div class="file-transfer-bar" id="bar-${transferId}"></div>
      </div>
      <div class="file-transfer-status">
        <span id="status-${transferId}">${dirText}...</span>
        <span id="pct-${transferId}">0%</span>
      </div>
    `;
    filesTransferList.prepend(item);
  }

  function updateTransferProgress(transferId, pct, statusText) {
    const bar = document.getElementById("bar-" + transferId);
    const pctEl = document.getElementById("pct-" + transferId);
    const statusEl = document.getElementById("status-" + transferId);
    if (bar) bar.style.width = Math.min(100, Math.max(0, pct)) + "%";
    if (pctEl) pctEl.textContent = Math.min(100, Math.max(0, pct)) + "%";
    if (statusEl && statusText) statusEl.textContent = statusText;
  }

  function completeTransferUI(transferId, statusText, isError) {
    const bar = document.getElementById("bar-" + transferId);
    const statusEl = document.getElementById("status-" + transferId);
    const pctEl = document.getElementById("pct-" + transferId);
    if (bar) {
      bar.style.width = "100%";
      bar.className = "file-transfer-bar " + (isError ? "error" : "done");
    }
    if (pctEl) pctEl.textContent = isError ? "Ошибка" : "100%";
    if (statusEl) statusEl.textContent = statusText;
  }

  async function sendFile(file) {
    if (!file) return;
    toggleFilesDrawer(true);

    const transferId = "f_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7);
    const totalChunks = Math.ceil(file.size / FILE_CHUNK_SIZE) || 1;

    createTransferUI(transferId, file.name, file.size, "upload");

    sendControlMessage({
      type: "file_start",
      transfer_id: transferId,
      filename: file.name,
      size: file.size,
      total_chunks: totalChunks
    });

    try {
      for (let i = 0; i < totalChunks; i++) {
        const start = i * FILE_CHUNK_SIZE;
        const end = Math.min(file.size, start + FILE_CHUNK_SIZE);
        const slice = file.slice(start, end);
        const arrayBuf = await slice.arrayBuffer();

        let binary = "";
        const bytes = new Uint8Array(arrayBuf);
        const len = bytes.byteLength;
        for (let b = 0; b < len; b++) {
          binary += String.fromCharCode(bytes[b]);
        }
        const b64 = btoa(binary);

        sendControlMessage({
          type: "file_chunk",
          transfer_id: transferId,
          chunk_index: i,
          data: b64
        });

        const pct = Math.round(((i + 1) / totalChunks) * 100);
        updateTransferProgress(transferId, pct, `Отправка (${i + 1}/${totalChunks})...`);

        if (inputChannel && inputChannel.bufferedAmount > 65536) {
          await new Promise((r) => setTimeout(r, 20));
        } else if (i % 4 === 0) {
          await new Promise((r) => setTimeout(r, 4));
        }
      }

      sendControlMessage({
        type: "file_end",
        transfer_id: transferId
      });

      completeTransferUI(transferId, "Сохранено в Downloads/LigamentSupport ✅", false);
      appendChatMessage({
        type: "chat_message",
        id: String(Date.now()),
        sender: "operator",
        sender_name: "Система",
        text: `📁 Передан файл: ${file.name} (${formatBytes(file.size)})`,
        timestamp: Date.now()
      });
    } catch (err) {
      console.error("Support file transfer error:", err);
      completeTransferUI(transferId, "Ошибка передачи: " + err.message, true);
    }
  }

  async function handleFilesUpload(fileList) {
    if (!fileList || fileList.length === 0) return;
    for (const file of fileList) {
      await sendFile(file);
    }
  }

  // Прием входящих файлов от клиента
  function handleIncomingFileStart(msg) {
    const transferId = msg.transfer_id || msg.id;
    if (!transferId) return;
    incomingDownloads.set(transferId, {
      filename: msg.filename || "client_file",
      size: msg.size || 0,
      totalChunks: msg.total_chunks || 1,
      chunks: new Map()
    });
    toggleFilesDrawer(true);
    createTransferUI(transferId, msg.filename || "client_file", msg.size || 0, "download");
  }

  function handleIncomingFileChunk(msg) {
    const transferId = msg.transfer_id || msg.id;
    const item = incomingDownloads.get(transferId);
    if (!item || !msg.data) return;

    try {
      const binary = atob(msg.data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      item.chunks.set(msg.chunk_index, bytes);

      const receivedCount = item.chunks.size;
      const pct = Math.round((receivedCount / item.totalChunks) * 100);
      updateTransferProgress(transferId, pct, `Прием (${receivedCount}/${item.totalChunks})...`);
    } catch (e) {
      console.error("Support incoming chunk decode error:", e);
    }
  }

  function handleIncomingFileEnd(msg) {
    const transferId = msg.transfer_id || msg.id;
    const item = incomingDownloads.get(transferId);
    if (!item) return;

    const parts = [];
    for (let i = 0; i < item.totalChunks; i++) {
      if (item.chunks.has(i)) {
        parts.push(item.chunks.get(i));
      }
    }

    try {
      const blob = new Blob(parts);
      // Файл НЕ скачивается автоматически: сохраняем blob-URL и показываем
      // оператору явную кнопку подтверждения в чате (скачивание только по клику).
      const url = URL.createObjectURL(blob);
      pendingIncomingFiles.set(transferId, { url, filename: item.filename });

      completeTransferUI(transferId, "Готов к скачиванию — подтвердите в чате ⏳", false);
      appendFileDownloadMessage(transferId, item.filename, item.size);
      playSosChime();
    } catch (e) {
      console.error("Support incoming file save error:", e);
      completeTransferUI(transferId, "Ошибка сборки файла", true);
    } finally {
      incomingDownloads.delete(transferId);
    }
  }

  // Сообщение в чате с явной кнопкой скачивания полученного файла.
  // Скачивание выполняется только по клику оператора (подтверждение получения).
  function appendFileDownloadMessage(transferId, filename, size) {
    if (!chatMessagesContainer) return;
    const safeId = window.CSS && CSS.escape ? CSS.escape(String(transferId)) : String(transferId).replace(/["\\\]]/g, "_");
    if (chatMessagesContainer.querySelector(`[data-msg-id="filedl_${safeId}"]`)) {
      return;
    }
    const emptyHint = chatMessagesContainer.querySelector(".chat-empty-hint");
    if (emptyHint) emptyHint.remove();

    const el = document.createElement("div");
    el.className = "chat-msg chat-msg-in";
    el.dataset.msgId = "filedl_" + transferId;
    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    el.innerHTML = `
      <div class="chat-msg-meta">
        <strong>Система</strong>
        <span>${timeStr}</span>
      </div>
      <div class="chat-msg-text">📁 Получен файл: ${escapeHtml(filename)} (${formatBytes(size || 0)})</div>
      <button type="button" style="display:block;width:100%;margin-top:8px;padding:8px 10px;border:none;border-radius:8px;cursor:pointer;background:#0284c7;color:#fff;font-size:13px;font-weight:600;text-align:center;">⬇ Скачать полученный файл: ${escapeHtml(filename)}</button>
    `;

    const btn = el.querySelector("button");
    btn.addEventListener("click", () => {
      const entry = pendingIncomingFiles.get(transferId);
      if (!entry) {
        btn.disabled = true;
        btn.textContent = "Файл больше не доступен — запросите повторную передачу";
        return;
      }
      try {
        const a = document.createElement("a");
        a.href = entry.url;
        a.download = entry.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } catch (e) {
        console.error("Support file download click error:", e);
      }
      pendingIncomingFiles.delete(transferId);
      // Отложенный revoke: браузеру нужно время на начало загрузки blob-URL
      setTimeout(() => URL.revokeObjectURL(entry.url), 60000);
      btn.disabled = true;
      btn.textContent = "✅ Скачано: " + entry.filename;
      const statusEl = document.getElementById("status-" + transferId);
      if (statusEl) statusEl.textContent = "Скачан в загрузки браузера ✅";
    });

    chatMessagesContainer.appendChild(el);
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
  }

  if (btnFilesToggle) {
    btnFilesToggle.addEventListener("click", () => toggleFilesDrawer());
  }
  if (btnFilesClose) {
    btnFilesClose.addEventListener("click", () => toggleFilesDrawer(false));
  }
  if (btnSelectFile && fileUploadInput) {
    btnSelectFile.addEventListener("click", () => fileUploadInput.click());
  }
  if (filesDropzone && fileUploadInput) {
    filesDropzone.addEventListener("click", (e) => {
      if (e.target !== btnSelectFile) fileUploadInput.click();
    });
    filesDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      filesDropzone.classList.add("drag-active");
    });
    filesDropzone.addEventListener("dragleave", () => {
      filesDropzone.classList.remove("drag-active");
    });
    filesDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      filesDropzone.classList.remove("drag-active");
      if (e.dataTransfer && e.dataTransfer.files) {
        handleFilesUpload(e.dataTransfer.files);
      }
    });
  }
  if (fileUploadInput) {
    fileUploadInput.addEventListener("change", () => {
      handleFilesUpload(fileUploadInput.files);
      fileUploadInput.value = "";
    });
  }

  // Drag & drop onto screen container
  if (viewerScreenContainer && canvasDropOverlay) {
    viewerScreenContainer.addEventListener("dragover", (e) => {
      e.preventDefault();
      canvasDropOverlay.classList.add("active");
    });
    viewerScreenContainer.addEventListener("dragleave", (e) => {
      if (!e.relatedTarget || !viewerScreenContainer.contains(e.relatedTarget)) {
        canvasDropOverlay.classList.remove("active");
      }
    });
    viewerScreenContainer.addEventListener("drop", (e) => {
      e.preventDefault();
      canvasDropOverlay.classList.remove("active");
      if (e.dataTransfer && e.dataTransfer.files) {
        handleFilesUpload(e.dataTransfer.files);
      }
    });
  }

  async function endSession() {
    if (!confirm("Завершить текущий сеанс удаленного доступа?")) return;
    try {
      const url = "/api/v1/admin/support/sessions/" + sessionID + "/end" + tokenQuery();
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
    } catch (_) {}
    location.href = "/admin/support";
  }

  async function openTransferModal() {
    if (!transferModal) return;
    transferModal.classList.add("visible");
    try {
      const url = "/api/v1/admin/support/sessions/" + sessionID + "/transfer" + tokenQuery();
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
      const data = await res.json();
      if (data && data.invite_url && transferLinkInput) {
        transferLinkInput.value = data.invite_url;
      }
    } catch (e) {
      console.error("Transfer init error:", e);
    }
  }

  function closeTransferModal() {
    if (!transferModal) return;
    transferModal.classList.remove("visible");
  }

  async function copyTransferLink() {
    if (!transferLinkInput) return;
    transferLinkInput.select();
    try {
      await navigator.clipboard.writeText(transferLinkInput.value);
      alert("Ссылка скопирована в буфер обмена!");
    } catch (_) {
      alert("Скопируйте ссылку вручную из поля ввода.");
    }
  }

  async function submitTransfer() {
    if (!transferUserSelect) return;
    const toUserID = transferUserSelect.value;
    if (!toUserID) {
      alert("Выберите сотрудника для переадресации.");
      return;
    }

    try {
      const url = "/api/v1/admin/support/sessions/" + sessionID + "/transfer" + tokenQuery();
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_user_id: toUserID })
      });
      if (res.ok) {
        alert("Сессия успешно переадресована сотруднику!");
        closeTransferModal();
      } else {
        alert("Ошибка переадресации.");
      }
    } catch (e) {
      alert("Ошибка отправки запроса: " + e.message);
    }
  }

  // Обработчики data-action
  for (const btn of document.querySelectorAll("[data-action]")) {
    const action = btn.dataset.action;
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      switch (action) {
        case "toggle-control":
          toggleInputControl();
          break;
        case "open-transfer":
          openTransferModal();
          break;
        case "close-transfer":
          closeTransferModal();
          break;
        case "copy-transfer":
          copyTransferLink();
          break;
        case "submit-transfer":
          submitTransfer();
          break;
        case "end-session":
          endSession();
          break;
        case "retry-connect":
          startConnectFlow();
          break;
      }
    });
  }

  // Авто-активация управления, если режим full_control
  if (accessMode === "full_control") {
    isControlEnabled = true;
    if (btnToggleControl) {
      btnToggleControl.className = "hud-btn hud-btn-control active";
      btnToggleControl.textContent = "✓ Управление активно";
    }
    setupInputCapture();
  }

  // Режим чата или автоматического подключения к экрану
  const urlParams = new URLSearchParams(window.location.search);
  const isChatOnly = urlParams.get("chat") === "1";
  const btnRequestScreen = document.getElementById("btn-request-screen");
  const chatOnlyPrompt = document.getElementById("chat-only-prompt");
  const btnStartScreenPrompt = document.getElementById("btn-start-screen-prompt");

  function initiateScreenShare() {
    if (chatOnlyPrompt) chatOnlyPrompt.style.display = "none";
    if (btnRequestScreen) btnRequestScreen.style.display = "none";
    const spinner = document.getElementById("viewer-spinner");
    if (spinner) spinner.style.display = "block";
    startConnectFlow();
  }

  if (btnRequestScreen) {
    btnRequestScreen.addEventListener("click", initiateScreenShare);
  }
  if (btnStartScreenPrompt) {
    btnStartScreenPrompt.addEventListener("click", initiateScreenShare);
  }

  // Инициализация WebSockets и WebRTC
  initWS();
  if (isChatOnly) {
    toggleChatDrawer(true);
    if (btnRequestScreen) btnRequestScreen.style.display = "inline-flex";
    if (chatOnlyPrompt) chatOnlyPrompt.style.display = "block";
    const spinner = document.getElementById("viewer-spinner");
    if (spinner) spinner.style.display = "none";
    if (connectionStatusText) {
      connectionStatusText.textContent = "Режим чата по заявке (доступ к экрану не запрашивался)";
    }
  } else {
    startConnectFlow();
  }
});

