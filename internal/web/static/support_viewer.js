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

  if (btnAddCategoryRow && categoriesTbody) {
    btnAddCategoryRow.addEventListener("click", () => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><input type="text" name="cat_id[]" class="input sm mono" required placeholder="it"></td>
        <td><input type="text" name="cat_title[]" class="input sm" required placeholder="Новая служба"></td>
        <td><input type="text" name="cat_icon[]" class="input sm" style="text-align: center;" value="🛟"></td>
        <td><input type="text" name="cat_emails[]" class="input sm" placeholder="support@corp.ru"></td>
        <td><input type="text" name="cat_telegram[]" class="input sm mono" placeholder="-100..."></td>
        <td style="text-align: center;"><button type="button" class="btn ghost sm danger cat-row-del" title="Удалить">✕</button></td>
      `;
      categoriesTbody.appendChild(tr);
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
  if (btnFullscreen) {
    btnFullscreen.addEventListener("click", () => {
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
    });

    document.addEventListener("fullscreenchange", () => {
      if (document.fullscreenElement) {
        btnFullscreen.classList.add("active");
        btnFullscreen.title = "Выйти из полноэкранного режима (Esc)";
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
  if (btnBlockInput) {
    btnBlockInput.addEventListener("click", () => {
      isClientInputBlocked = !isClientInputBlocked;
      sendControlMessage({ type: "block_input", enabled: isClientInputBlocked });
      if (isClientInputBlocked) {
        btnBlockInput.classList.add("active");
        btnBlockInput.textContent = "🔓 Разблок ввода клиента";
      } else {
        btnBlockInput.classList.remove("active");
        btnBlockInput.textContent = "🔒 Блок ввода клиента";
      }
    });
  }

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

  // Инициализация WebSockets и WebRTC
  initWS();
  startConnectFlow();
});

