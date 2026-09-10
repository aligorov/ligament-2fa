// twofa: консоль удаленной поддержки (SOS) и WebRTC просмотрщик экрана.
// Полностью соответствует Content-Security-Policy (без inline-скриптов и inline-обработчиков).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const viewerEl = document.getElementById("support-viewer");
  if (!viewerEl) return;

  const sessionID = viewerEl.dataset.sessionId;
  const wsEndpoint = viewerEl.dataset.wsEndpoint;
  const transferToken = viewerEl.dataset.transferToken || "";
  const operatorName = viewerEl.dataset.operatorName || "Инженер поддержки";

  let ws = null;
  let peerConnection = null;
  let inputChannel = null;
  let isControlEnabled = false;
  let isClientInputBlocked = false;
  let currentZoom = 1.0;

  const statusBadge = document.getElementById("session-status-badge");
  const numberMatchCard = document.getElementById("number-match-card");
  const numberMatchDigits = document.getElementById("number-match-digits");
  const connectionStatusText = document.getElementById("connection-status-text");
  const videoPlaceholder = document.getElementById("video-placeholder");
  const remoteVideo = document.getElementById("remote-video");
  const btnToggleControl = document.getElementById("btn-toggle-control");
  const transferModal = document.getElementById("transfer-modal");
  const transferUserSelect = document.getElementById("transfer-user-select");
  const transferLinkInput = document.getElementById("transfer-link-input");

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
  const viewerAccessMode = document.getElementById("viewer-access-mode");

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
      connectionStatusText.textContent = "Ожидание 2FA подтверждения клиентом...";
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
        if (statusBadge) statusBadge.textContent = "Подключено (P2P)";
      } else if (peerConnection.connectionState === "failed" || peerConnection.connectionState === "disconnected") {
        if (statusBadge) statusBadge.textContent = "Связь потеряна";
      }
    };

    peerConnection.oniceconnectionstatechange = () => {
      console.log("Support WebRTC: ICE state ->", peerConnection.iceConnectionState);
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
          statusBadge.textContent = "Активно (Трансляция)";
        }
      }

      if (track) {
        track.onunmute = () => {
          console.log("Support WebRTC: Track unmuted (receiving video frames)");
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
          playPromise
            .then(() => {
              console.log("Support WebRTC: Video playing");
              onStreamReady();
            })
            .catch((e) => console.warn("Video play notice:", e));
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

    // Создаем DataChannel для отправки команд ввода оператора
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
        if (msg.cpu_warning || msg.cpu_percent >= 95) {
          telCpuBadge.className = "badge danger";
        } else {
          telCpuBadge.className = "badge ok";
        }
      }
      if (telDiskBadge && msg.disk_free_gb !== undefined) {
        telDiskBadge.textContent = `💾 Диск: ${msg.disk_free_gb} ГБ (${msg.disk_percent}%)`;
        if (msg.disk_warning || msg.disk_free_gb < 10) {
          telDiskBadge.className = "badge danger";
        } else {
          telDiskBadge.className = "badge ok";
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
      // Сбрасываем накопленные ICE кандидаты, пришедшие раньше SDP оффера
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
      if (statusBadge) {
        statusBadge.textContent = "Подтверждено (подключение...)";
      }
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
      ws.onopen = () => {
        console.log("Support WebSocket connected");
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleWSMessage(msg);
        } catch (e) {
          console.error("Support WS parse error:", e);
        }
      };
      ws.onerror = (e) => {
        console.warn("Support WS connection error:", e);
      };
      ws.onclose = () => {
        console.log("Support WebSocket closed");
      };
    } catch (e) {
      console.error("Support WS init error:", e);
    }
  }

  function toggleInputControl() {
    isControlEnabled = !isControlEnabled;
    if (!btnToggleControl) return;

    if (isControlEnabled) {
      btnToggleControl.className = "btn ok sm";
      btnToggleControl.textContent = "✓ Управление активно";
      setupInputCapture();
      if (viewerAccessMode) viewerAccessMode.textContent = "Полное управление";
    } else {
      btnToggleControl.className = "btn secondary sm";
      btnToggleControl.textContent = "🎮 Включить управление";
      removeInputCapture();
      if (viewerAccessMode) viewerAccessMode.textContent = "Только просмотр";
    }
  }

  function onContextMenu(e) {
    if (isControlEnabled) {
      e.preventDefault();
    }
  }

  function onMouseMove(e) {
    if (!isControlEnabled) return;
    const rect = remoteVideo.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const x = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const y = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));
    sendControlMessage({ type: "mouse_move", action: "mouse_move", x, y });
  }

  function onMouseDown(e) {
    if (!isControlEnabled) return;
    e.preventDefault();
    const rect = remoteVideo.getBoundingClientRect();
    const x = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const y = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));
    sendControlMessage({ type: "mouse_down", action: "mouse_down", button: e.button, x, y });
  }

  function onMouseUp(e) {
    if (!isControlEnabled) return;
    e.preventDefault();
    const rect = remoteVideo.getBoundingClientRect();
    const x = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const y = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));
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

  // Масштабирование видео
  if (btnScaleFit && remoteVideo) {
    btnScaleFit.addEventListener("click", () => {
      currentZoom = 1.0;
      remoteVideo.style.objectFit = "contain";
      remoteVideo.style.width = "100%";
      remoteVideo.style.height = "auto";
      remoteVideo.style.maxHeight = "80vh";
      remoteVideo.style.transform = "none";
      btnScaleFit.className = "btn primary sm";
      if (btnScaleOrig) btnScaleOrig.className = "btn ghost sm";
    });
  }

  if (btnScaleOrig && remoteVideo) {
    btnScaleOrig.addEventListener("click", () => {
      currentZoom = 1.0;
      remoteVideo.style.objectFit = "none";
      remoteVideo.style.width = "auto";
      remoteVideo.style.height = "auto";
      remoteVideo.style.maxHeight = "none";
      remoteVideo.style.transform = "none";
      btnScaleOrig.className = "btn primary sm";
      if (btnScaleFit) btnScaleFit.className = "btn ghost sm";
    });
  }

  if (btnScaleIn && remoteVideo) {
    btnScaleIn.addEventListener("click", () => {
      currentZoom = Math.min(currentZoom + 0.2, 3.0);
      remoteVideo.style.transform = `scale(${currentZoom})`;
    });
  }

  if (btnScaleOut && remoteVideo) {
    btnScaleOut.addEventListener("click", () => {
      currentZoom = Math.max(currentZoom - 0.2, 0.4);
      remoteVideo.style.transform = `scale(${currentZoom})`;
    });
  }

  // Переключение монитора
  if (viewerScreenSelect) {
    viewerScreenSelect.addEventListener("change", () => {
      const scrID = viewerScreenSelect.value;
      sendControlMessage({ type: "switch_screen", screen_id: scrID });
    });
  }

  // Блокировка клавиатуры и мыши клиента
  if (btnBlockInput) {
    btnBlockInput.addEventListener("click", () => {
      isClientInputBlocked = !isClientInputBlocked;
      sendControlMessage({ type: "block_input", enabled: isClientInputBlocked });
      if (isClientInputBlocked) {
        btnBlockInput.className = "btn err sm";
        btnBlockInput.textContent = "🔓 Разблок ввода";
        btnBlockInput.title = "Разблокировать клавиатуру и мышь клиента";
      } else {
        btnBlockInput.className = "btn secondary sm";
        btnBlockInput.textContent = "🔒 Блок ввода клиента";
        btnBlockInput.title = "Заблокировать локальную клавиатуру и мышь у клиента";
      }
    });
  }

  // Горячие клавиши
  if (viewerHotkeySelect) {
    viewerHotkeySelect.addEventListener("change", () => {
      const hotkey = viewerHotkeySelect.value;
      if (!hotkey) return;
      sendControlMessage({ type: "hotkey", key: hotkey });
      viewerHotkeySelect.value = "";
    });
  }

  // Буфер обмена
  if (btnClipboardToggle && clipboardDrawer) {
    btnClipboardToggle.addEventListener("click", () => {
      const isHidden = clipboardDrawer.style.display === "none";
      clipboardDrawer.style.display = isHidden ? "block" : "none";
    });
  }

  if (btnClipboardClose && clipboardDrawer) {
    btnClipboardClose.addEventListener("click", () => {
      clipboardDrawer.style.display = "none";
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

  // Навешивание обработчиков событий (без inline onclick)
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

  // Запуск WebSockets и инициализации подключения
  initWS();
  startConnectFlow();
});
