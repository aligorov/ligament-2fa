// twofa: мелкие UI-улучшения без фреймворков: кнопки «Скопировать»
// (data-copy копирует текст соседнего code-элемента в буфер обмена),
// подтверждение опасных действий (data-confirm — вместо инлайн-onclick,
// запрещённого CSP) и выбор пресета SMS-шлюза в настройках
// (data-sms-preset).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // Опасное действие: кнопка data-confirm в форме требует confirm() до
  // отправки (перехват на submit — покрывает и Enter в поле формы).
  for (const btn of document.querySelectorAll("[data-confirm]")) {
    const form = btn.closest("form");
    if (!form) continue;
    form.addEventListener("submit", (e) => {
      if (!confirm(btn.dataset.confirm)) e.preventDefault();
    });
  }

  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", async () => {
      const row = btn.closest(".copy-row");
      // linkcode — настоящий код; plain <code> — только если кода нет в строке
      const src = (row && row.querySelector(".linkcode, code")) ||
        btn.closest(".card")?.querySelector(".linkcode");
      if (!src) return;
      try {
        await navigator.clipboard.writeText(src.textContent.trim());
        const label = btn.textContent;
        btn.textContent = "Скопировано ✓";
        btn.disabled = true;
        setTimeout(() => { btn.textContent = label; btn.disabled = false; }, 2000);
      } catch (e) {
        // Буфер недоступен (нет https/разрешения) — код остаётся выделяемым.
        btn.textContent = "Выделите вручную";
        setTimeout(() => { btn.textContent = "Скопировать"; }, 2000);
      }
    });
  }

  // Запрос кода подтверждения на доступный канал (Telegram / Email / SMS)
  for (const btn of document.querySelectorAll("[data-request-code]")) {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      const field = btn.closest(".field") || btn.closest(".field-with-btn")?.closest(".field");
      let statusEl = field ? field.querySelector(".request-code-status") : null;
      if (!statusEl && field) {
        statusEl = document.createElement("span");
        statusEl.className = "request-code-status";
        field.appendChild(statusEl);
      }

      const metaCsrf = document.querySelector('meta[name="csrf-token"]')?.content;
      const formCsrf = btn.closest("form")?.querySelector('input[name="csrf_token"]')?.value ||
                       document.querySelector('input[name="csrf_token"]')?.value;
      const csrf = metaCsrf || formCsrf || "";

      const origText = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Отправка…";

      const setStatus = (msg, isOk) => {
        if (statusEl) {
          statusEl.textContent = msg;
          statusEl.className = "request-code-status " + (isOk ? "ok" : "err");
        }
      };

      try {
        const formData = new FormData();
        if (csrf) formData.append("csrf_token", csrf);

        const chanSelect = btn.closest("form")?.querySelector('select[name="channel"]') ||
                           document.querySelector('select[name="channel"]');
        if (chanSelect && chanSelect.value) {
          formData.append("channel", chanSelect.value);
        }

        const res = await fetch("/me/send-code", {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "X-CSRF-Token": csrf,
          },
          body: formData,
        });

        const data = await res.json().catch(() => null);
        if (res.ok && data && data.ok) {
          setStatus("✅ " + (data.message || "Код подтверждения отправлен."), true);
          const codeInput = field?.querySelector('input[name="code"]') ||
                            btn.closest(".field-with-btn")?.querySelector('input[name="code"]');
          if (codeInput) {
            codeInput.focus();
          }
          let countdown = 60;
          btn.textContent = `Повторить (${countdown}с)`;
          const timer = setInterval(() => {
            countdown--;
            if (countdown <= 0) {
              clearInterval(timer);
              btn.disabled = false;
              btn.textContent = origText;
            } else {
              btn.textContent = `Повторить (${countdown}с)`;
            }
          }, 1000);
        } else {
          const errMsg = data?.message || (res.status === 429 ? "Подождите перед повторной отправкой." : "Не удалось отправить код.");
          setStatus("⚠️ " + errMsg, false);
          btn.disabled = false;
          btn.textContent = origText;
        }
      } catch (err) {
        setStatus("⚠️ Ошибка сети при запросе кода.", false);
        btn.disabled = false;
        btn.textContent = origText;
      }
    });
  }

  // Пресет SMS-шлюза: JSON конфига выбранной option (data-config, креды
  // пустые) — в textarea sms.gateway; описание пресета — в подсказку.
  const presetSel = document.querySelector("[data-sms-preset]");
  if (presetSel) {
    const desc = document.querySelector("[data-sms-preset-desc]");
    const gateway = document.querySelector('textarea[name="sms.gateway"]');
    presetSel.addEventListener("change", () => {
      const opt = presetSel.selectedOptions[0];
      if (!opt || !opt.value) return;
      if (desc && opt.dataset.description) {
        desc.textContent = opt.dataset.description;
      }
      if (gateway && opt.dataset.config) {
        try {
          gateway.value = JSON.stringify(JSON.parse(opt.dataset.config), null, 2);
        } catch (e) {
          gateway.value = opt.dataset.config; // конфиг не JSON — как есть
        }
      }
    });
  }

  // Интерактивный визуальный конструктор RADIUS-атрибутов по группам AD
  initGroupRadiusBuilder();
});

function initGroupRadiusBuilder() {
  const container = document.getElementById("gr-groups-container");
  const rawInput = document.getElementById("ldap-group-radius-raw");
  const emptyState = document.getElementById("gr-empty-state");
  const jsonPreview = document.getElementById("gr-json-preview");
  if (!container || !rawInput) return;

  function attrCountLabel(n) {
    if (n % 10 === 1 && n % 100 !== 11) return `${n} атрибут`;
    if (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20)) return `${n} атрибута`;
    return `${n} атрибутов`;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function syncData() {
    const cards = container.querySelectorAll(".gr-card");
    const result = {};

    cards.forEach((card) => {
      const groupNameInput = card.querySelector(".gr-group-name");
      const groupName = groupNameInput ? groupNameInput.value.trim() : "";
      const countBadge = card.querySelector(".gr-attr-count");
      const rows = card.querySelectorAll(".gr-attr-row");

      let validAttrs = 0;
      const attrs = {};
      rows.forEach((row) => {
        const keyInput = row.querySelector(".gr-attr-key");
        const valInput = row.querySelector(".gr-attr-val");
        const k = keyInput ? keyInput.value.trim() : "";
        const v = valInput ? valInput.value.trim() : "";
        if (k) {
          attrs[k] = v;
          validAttrs++;
        }
      });

      if (countBadge) {
        countBadge.textContent = attrCountLabel(validAttrs);
      }

      if (groupName) {
        result[groupName] = attrs;
      }
    });

    const hasCards = cards.length > 0;
    if (emptyState) {
      emptyState.style.display = hasCards ? "none" : "flex";
    }

    const jsonStr = JSON.stringify(result, null, 2);
    rawInput.value = jsonStr;
    if (jsonPreview) {
      jsonPreview.textContent = jsonStr;
    }
  }

  function createAttrRow(key = "", val = "") {
    const tr = document.createElement("tr");
    tr.className = "gr-attr-row";
    tr.innerHTML = `
      <td>
        <input type="text" class="input mono sm gr-attr-key" list="radius-common-attrs" placeholder="Атрибут (напр. Filter-Id)" value="${escapeHtml(key)}">
      </td>
      <td>
        <input type="text" class="input mono sm gr-attr-val" placeholder="Значение" value="${escapeHtml(val)}">
      </td>
      <td style="text-align: center;">
        <button type="button" class="btn sm ghost danger gr-btn-delete-attr" title="Удалить атрибут">✕</button>
      </td>
    `;

    tr.querySelectorAll("input").forEach((inp) => {
      inp.addEventListener("input", syncData);
    });

    const delBtn = tr.querySelector(".gr-btn-delete-attr");
    if (delBtn) {
      delBtn.addEventListener("click", () => {
        const tbody = tr.closest("tbody");
        tr.remove();
        if (tbody && tbody.querySelectorAll(".gr-attr-row").length === 0) {
          tbody.appendChild(createAttrRow("", ""));
        }
        syncData();
      });
    }

    return tr;
  }

  function createGroupCard(groupName = "", attrs = {}) {
    const card = document.createElement("div");
    card.className = "gr-card";
    card.innerHTML = `
      <div class="gr-card-head">
        <div class="gr-group-input-wrap">
          <span class="gr-group-icon">👥</span>
          <input type="text" class="input gr-group-name" placeholder="Имя группы в AD (напр. VPN-Users или полный DN)" value="${escapeHtml(groupName)}">
        </div>
        <div class="gr-card-head-actions">
          <span class="badge neutral gr-attr-count">0 атрибутов</span>
          <button type="button" class="btn sm ghost danger gr-btn-delete-group" title="Удалить группу">🗑️ Удалить</button>
        </div>
      </div>
      <div class="gr-card-body">
        <div class="gr-attrs-table-wrap">
          <table class="table compact gr-attrs-table">
            <thead>
              <tr>
                <th style="width: 48%;">Атрибут RADIUS</th>
                <th style="width: 44%;">Значение</th>
                <th style="width: 8%; text-align: center;"></th>
              </tr>
            </thead>
            <tbody class="gr-attrs-tbody"></tbody>
          </table>
        </div>
        <div class="gr-card-foot">
          <button type="button" class="btn sm secondary gr-btn-add-attr">➕ Добавить атрибут</button>
          <span class="help muted">Двойной клик на имя атрибута открывает список частых параметров.</span>
        </div>
      </div>
    `;

    const tbody = card.querySelector(".gr-attrs-tbody");
    const entries = Object.entries(attrs || {});
    if (entries.length > 0) {
      entries.forEach(([k, v]) => {
        tbody.appendChild(createAttrRow(k, v));
      });
    } else {
      tbody.appendChild(createAttrRow("", ""));
    }

    const nameInput = card.querySelector(".gr-group-name");
    if (nameInput) {
      nameInput.addEventListener("input", syncData);
    }

    const addAttrBtn = card.querySelector(".gr-btn-add-attr");
    if (addAttrBtn) {
      addAttrBtn.addEventListener("click", () => {
        const row = createAttrRow("", "");
        tbody.appendChild(row);
        const kInp = row.querySelector(".gr-attr-key");
        if (kInp) kInp.focus();
        syncData();
      });
    }

    const delGroupBtn = card.querySelector(".gr-btn-delete-group");
    if (delGroupBtn) {
      delGroupBtn.addEventListener("click", () => {
        card.remove();
        syncData();
      });
    }

    return card;
  }

  // Парсинг начальных данных из hidden поля
  let initial = {};
  try {
    const rawVal = rawInput.value.trim();
    if (rawVal) {
      initial = JSON.parse(rawVal);
    }
  } catch (e) {
    initial = {};
  }

  container.innerHTML = "";
  if (initial && typeof initial === "object" && !Array.isArray(initial)) {
    const keys = Object.keys(initial);
    if (keys.length > 0) {
      keys.forEach((groupName) => {
        const card = createGroupCard(groupName, initial[groupName]);
        container.appendChild(card);
      });
    }
  }

  syncData();

  // Кнопка добавления новой группы
  const addGroupBtn = document.querySelector("[data-gr-add-group]");
  if (addGroupBtn) {
    addGroupBtn.addEventListener("click", () => {
      const card = createGroupCard("", {});
      container.appendChild(card);
      const nameInput = card.querySelector(".gr-group-name");
      if (nameInput) nameInput.focus();
      syncData();
    });
  }

  // Быстрые шаблоны
  document.querySelectorAll("[data-gr-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = btn.dataset.grPreset;
      if (p === "vpn") {
        const card = createGroupCard("VPN-Users", {
          "Filter-Id": "vpn_allow",
          "Session-Timeout": "28800"
        });
        container.appendChild(card);
      } else if (p === "mikrotik") {
        const card = createGroupCard("Network-Admins", {
          "Mikrotik-Group": "full-access",
          "Session-Timeout": "14400"
        });
        container.appendChild(card);
      } else if (p === "wifi") {
        const card = createGroupCard("WiFi-Staff", {
          "Tunnel-Type": "13",
          "Tunnel-Medium-Type": "6",
          "Tunnel-Private-Group-Id": "100"
        });
        container.appendChild(card);
      }
      syncData();
    });
  });

  // Страховочная синхронизация перед отправкой формы
  const form = container.closest("form");
  if (form) {
    form.addEventListener("submit", syncData);
  }
}


