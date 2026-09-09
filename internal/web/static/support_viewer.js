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
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" }
      ]
    };

    peerConnection = new RTCPeerConnection(config);

    peerConnection.ontrack = (event) => {
      console.log("Support WebRTC: Remote track received", event);
      if (remoteVideo) {
        if (event.streams && event.streams[0]) {
          remoteVideo.srcObject = event.streams[0];
        } else if (event.track) {
          if (!remoteVideo.srcObject) {
            remoteVideo.srcObject = new MediaStream();
          }
          remoteVideo.srcObject.addTrack(event.track);
        }
        remoteVideo.play().catch((e) => console.warn("Video play notice:", e));
      }
      if (videoPlaceholder) {
        videoPlaceholder.classList.add("hidden");
      }
      hideNumberMatch();
      if (statusBadge) {
        statusBadge.textContent = "Активно (Трансляция)";
      }
    };

    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        sendSignal({ candidate: event.candidate });
      }
    };

    peerConnection.ondatachannel = (event) => {
      inputChannel = event.channel;
      console.log("Support WebRTC: Input DataChannel received from client");
    };

    // Создаем DataChannel для отправки команд ввода оператора
    try {
      inputChannel = peerConnection.createDataChannel("input", { ordered: true });
      inputChannel.onopen = () => console.log("Support WebRTC: Input DataChannel open");
    } catch (e) {
      console.warn("Support WebRTC: DataChannel creation note:", e);
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
    } else {
      btnToggleControl.className = "btn secondary sm";
      btnToggleControl.textContent = "🎮 Включить управление";
      removeInputCapture();
    }
  }

  function setupInputCapture() {
    if (!remoteVideo) return;
    remoteVideo.onmousemove = (e) => {
      if (!isControlEnabled || !inputChannel || inputChannel.readyState !== "open") return;
      const rect = remoteVideo.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width;
      const y = (e.clientY - rect.top) / rect.height;
      inputChannel.send(JSON.stringify({ type: "mouse_move", action: "mouse_move", x, y }));
    };
    remoteVideo.onmousedown = (e) => {
      if (!isControlEnabled || !inputChannel || inputChannel.readyState !== "open") return;
      inputChannel.send(JSON.stringify({ type: "mouse_down", action: "mouse_down", button: e.button }));
    };
    remoteVideo.onmouseup = (e) => {
      if (!isControlEnabled || !inputChannel || inputChannel.readyState !== "open") return;
      inputChannel.send(JSON.stringify({ type: "mouse_up", action: "mouse_up", button: e.button }));
    };
  }

  function removeInputCapture() {
    if (!remoteVideo) return;
    remoteVideo.onmousemove = null;
    remoteVideo.onmousedown = null;
    remoteVideo.onmouseup = null;
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
