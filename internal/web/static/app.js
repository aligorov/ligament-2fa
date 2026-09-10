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

  // Автообновление страниц с атрибутом data-auto-refresh (секунды)
  const refreshEl = document.querySelector("[data-auto-refresh]");
  if (refreshEl) {
    const sec = parseInt(refreshEl.dataset.autoRefresh, 10) || 6;
    const checkAndReload = () => {
      // Не перезагружать страницу, если открыто модальное окно или фокус в поле ввода
      const modalOpen = document.querySelector(".viewer-modal-backdrop.visible, .modal.visible, [id$='-modal'].visible");
      const activeEl = document.activeElement;
      const isTyping = activeEl && (activeEl.tagName === "INPUT" || activeEl.tagName === "TEXTAREA" || activeEl.tagName === "SELECT");
      if (!document.hidden && !modalOpen && !isTyping) {
        location.reload();
      } else {
        setTimeout(checkAndReload, sec * 1000);
      }
    };
    setTimeout(checkAndReload, sec * 1000);
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

  // Компактный список пользователей (поиск, фильтры, дропдаун действий, пагинация)
  initUsersTable();

  // Выбор участников локальных групп по группам Active Directory / LDAP
  initGroupsMemberSelector();

  // Панель настроек удаленной поддержки (категории и пороги телеметрии)
  initSupportSettingsPanel();

  // Polling статуса Number Match push-челленджа на странице логина
  initNumberMatchPolling();

  // Быстрые RADIUS-пресеты (data-radius-preset) и связка «селект VLAN —
  // поле VLAN ID» (data-vlan-input) — вместо инлайн-onclick/onchange,
  // запрещённых CSP
  initRadiusPresetButtons();
  initVLANSelects();

  // Цвет аватара пользователя из data-avatar-bg (динамический цвет из
  // шаблона нельзя вынести в статический CSS)
  initUserAvatarColors();

  // Шаблон «openidconnect.net» для нового OIDC-клиента
  initOIDCPlaygroundPreset();
});

function initGroupRadiusBuilder() {
  const container = document.getElementById("gr-groups-container");
  const rawInput = document.getElementById("ldap-group-radius-raw");
  const emptyState = document.getElementById("gr-empty-state");
  const jsonPreview = document.getElementById("gr-json-preview");
  if (!container || !rawInput) return;

  const vlanDataEl = document.getElementById("vlan-profiles-data");
  let vlanProfiles = {};
  if (vlanDataEl && vlanDataEl.dataset.profiles) {
    try {
      vlanProfiles = JSON.parse(vlanDataEl.dataset.profiles);
    } catch (e) {
      vlanProfiles = {};
    }
  }

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

      // Синхронизация селектора VLAN с атрибутами таблицы
      const vlanVal = attrs["Tunnel-Private-Group-Id"] || "";
      const vlanSelect = card.querySelector(".gr-group-vlan-select");
      const vlanCustom = card.querySelector(".gr-group-vlan-custom");
      if (vlanSelect && vlanCustom && document.activeElement !== vlanSelect && document.activeElement !== vlanCustom) {
        if (vlanVal && vlanProfiles[vlanVal]) {
          vlanSelect.value = vlanVal;
          vlanCustom.style.display = "none";
          vlanCustom.value = vlanVal;
        } else if (vlanVal) {
          vlanSelect.value = "custom";
          vlanCustom.value = vlanVal;
          vlanCustom.style.display = "";
        } else {
          vlanSelect.value = "";
          vlanCustom.value = "";
          vlanCustom.style.display = "none";
        }
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
    const currentVlan = (attrs && attrs["Tunnel-Private-Group-Id"]) || "";
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
      <div class="gr-vlan-selector-bar">
        <div class="gr-vlan-label">
          <span class="muted" style="font-weight: 500;">📶 VLAN (сегмент Wi-Fi):</span>
          <select class="select sm gr-group-vlan-select" style="max-width: 280px;">
            <option value="">— Без привязки к VLAN —</option>
            ${Object.entries(vlanProfiles).map(([id, name]) => `
              <option value="${escapeHtml(id)}" ${currentVlan === id ? "selected" : ""}>VLAN ${escapeHtml(id)} — ${escapeHtml(name)}</option>
            `).join("")}
            <option value="custom" ${currentVlan && !vlanProfiles[currentVlan] ? "selected" : ""}>Свой номер VLAN...</option>
          </select>
          <input type="text" class="input mono sm gr-group-vlan-custom" placeholder="VLAN ID" style="max-width: 90px; ${currentVlan && !vlanProfiles[currentVlan] ? "" : "display: none;"}" value="${escapeHtml(currentVlan)}">
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

    const vlanSelect = card.querySelector(".gr-group-vlan-select");
    const vlanCustom = card.querySelector(".gr-group-vlan-custom");

    function applyVLANToTable(vid) {
      vid = vid ? vid.trim() : "";
      const rows = tbody.querySelectorAll(".gr-attr-row");
      let found = false;
      rows.forEach((row) => {
        const kInp = row.querySelector(".gr-attr-key");
        const vInp = row.querySelector(".gr-attr-val");
        if (kInp && kInp.value.trim() === "Tunnel-Private-Group-Id") {
          found = true;
          if (vid) {
            vInp.value = vid;
          } else {
            row.remove();
          }
        }
      });
      if (!found && vid) {
        tbody.appendChild(createAttrRow("Tunnel-Private-Group-Id", vid));
      }
      if (tbody.querySelectorAll(".gr-attr-row").length === 0) {
        tbody.appendChild(createAttrRow("", ""));
      }
      syncData();
    }

    if (vlanSelect) {
      vlanSelect.addEventListener("change", () => {
        if (vlanSelect.value === "custom") {
          vlanCustom.style.display = "";
          vlanCustom.focus();
          applyVLANToTable(vlanCustom.value);
        } else {
          vlanCustom.style.display = "none";
          vlanCustom.value = vlanSelect.value;
          applyVLANToTable(vlanSelect.value);
        }
      });
    }

    if (vlanCustom) {
      vlanCustom.addEventListener("input", () => {
        applyVLANToTable(vlanCustom.value);
      });
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

function initUsersTable() {
  const table = document.getElementById("users-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll("tr.user-row"));
  const searchInput = document.getElementById("users-search");
  const searchClear = document.getElementById("users-search-clear");
  const pills = document.querySelectorAll(".users-pill");
  const paginationInfo = document.getElementById("users-pagination-info");
  const pageBtnsContainer = document.getElementById("users-page-btns");
  const perPageSelect = document.getElementById("users-per-page");
  const emptyMsg = document.getElementById("users-empty");

  // Статистика для бейджей на фильтр-чипсах
  let countAll = rows.length;
  let countLdap = 0;
  let countLocal = 0;
  let countAdmin = 0;
  let countDisabled = 0;

  rows.forEach((r) => {
    if (r.dataset.source === "ldap") countLdap++;
    else countLocal++;

    if (r.dataset.role === "admin") countAdmin++;
    if (r.dataset.enabled === "0") countDisabled++;
  });

  const elAll = document.getElementById("count-all");
  const elLdap = document.getElementById("count-ldap");
  const elLocal = document.getElementById("count-local");
  const elAdmin = document.getElementById("count-admin");
  const elDisabled = document.getElementById("count-disabled");

  if (elAll) elAll.textContent = countAll;
  if (elLdap) elLdap.textContent = countLdap;
  if (elLocal) elLocal.textContent = countLocal;
  if (elAdmin) elAdmin.textContent = countAdmin;
  if (elDisabled) elDisabled.textContent = countDisabled;

  let currentFilter = "all";
  let currentQuery = "";
  let currentPage = 1;

  function render() {
    const q = currentQuery.toLowerCase().trim();

    // Фильтрация
    const filtered = rows.filter((r) => {
      if (currentFilter === "ldap" && r.dataset.source !== "ldap") return false;
      if (currentFilter === "local" && r.dataset.source === "ldap") return false;
      if (currentFilter === "admin" && r.dataset.role !== "admin") return false;
      if (currentFilter === "disabled" && r.dataset.enabled !== "0") return false;

      if (q) {
        const u = (r.dataset.username || "").toLowerCase();
        const n = (r.dataset.name || "").toLowerCase();
        const e = (r.dataset.email || "").toLowerCase();
        const p = (r.dataset.phone || "").toLowerCase();
        const g = (r.dataset.groups || "").toLowerCase();
        if (!u.includes(q) && !n.includes(q) && !e.includes(q) && !p.includes(q) && !g.includes(q)) {
          return false;
        }
      }
      return true;
    });

    const total = filtered.length;
    const perPageVal = perPageSelect ? perPageSelect.value : "25";
    const isAll = perPageVal === "all";
    const pageSize = isAll ? Math.max(1, total) : (parseInt(perPageVal, 10) || 25);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));

    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = startIdx + pageSize;

    const visibleSet = new Set(filtered.slice(startIdx, endIdx));
    rows.forEach((r) => {
      r.style.display = visibleSet.has(r) ? "" : "none";
    });

    if (emptyMsg) {
      emptyMsg.style.display = total === 0 ? "block" : "none";
    }
    table.style.display = total === 0 ? "none" : "";

    if (paginationInfo) {
      if (total === 0) {
        paginationInfo.textContent = "Пользователи не найдены";
      } else {
        const from = startIdx + 1;
        const to = Math.min(total, endIdx);
        if (total === countAll) {
          paginationInfo.textContent = `Показано ${from}–${to} из ${total}`;
        } else {
          paginationInfo.textContent = `Показано ${from}–${to} из ${total} (найдено из ${countAll})`;
        }
      }
    }

    if (pageBtnsContainer) {
      pageBtnsContainer.innerHTML = "";
      if (totalPages > 1 && !isAll) {
        const prevBtn = document.createElement("button");
        prevBtn.type = "button";
        prevBtn.className = "page-btn";
        prevBtn.textContent = "«";
        prevBtn.disabled = currentPage === 1;
        prevBtn.title = "Предыдущая страница";
        prevBtn.addEventListener("click", () => {
          if (currentPage > 1) {
            currentPage--;
            render();
            scrollToTable();
          }
        });
        pageBtnsContainer.appendChild(prevBtn);

        const pagesToDisplay = getPageNumbers(currentPage, totalPages);
        pagesToDisplay.forEach((p) => {
          if (p === "...") {
            const ellipsis = document.createElement("span");
            ellipsis.className = "page-ellipsis";
            ellipsis.textContent = "…";
            ellipsis.style.padding = "0 4px";
            ellipsis.style.color = "var(--muted)";
            pageBtnsContainer.appendChild(ellipsis);
          } else {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "page-btn" + (p === currentPage ? " active" : "");
            btn.textContent = p;
            btn.addEventListener("click", () => {
              currentPage = p;
              render();
              scrollToTable();
            });
            pageBtnsContainer.appendChild(btn);
          }
        });

        const nextBtn = document.createElement("button");
        nextBtn.type = "button";
        nextBtn.className = "page-btn";
        nextBtn.textContent = "»";
        nextBtn.disabled = currentPage === totalPages;
        nextBtn.title = "Следующая страница";
        nextBtn.addEventListener("click", () => {
          if (currentPage < totalPages) {
            currentPage++;
            render();
            scrollToTable();
          }
        });
        pageBtnsContainer.appendChild(nextBtn);
      }
    }
  }

  function scrollToTable() {
    const box = table.getBoundingClientRect();
    if (box.top < 0) {
      table.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function getPageNumbers(current, total) {
    if (total <= 7) {
      const pages = [];
      for (let i = 1; i <= total; i++) pages.push(i);
      return pages;
    }
    if (current <= 4) {
      return [1, 2, 3, 4, 5, "...", total];
    }
    if (current >= total - 3) {
      return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
    }
    return [1, "...", current - 1, current, current + 1, "...", total];
  }

  // Дропдаун действий пользователя
  document.querySelectorAll(".user-dropdown-toggle").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const dropdown = btn.closest(".user-dropdown");
      const wasActive = dropdown.classList.contains("active");
      document.querySelectorAll(".user-dropdown.active").forEach((d) => d.classList.remove("active"));
      if (!wasActive) {
        dropdown.classList.add("active");
      }
    });
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".user-dropdown")) {
      document.querySelectorAll(".user-dropdown.active").forEach((d) => d.classList.remove("active"));
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".user-dropdown.active").forEach((d) => d.classList.remove("active"));
    }
  });

  // Обработчики тулбара поиска и фильтров
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      currentQuery = searchInput.value;
      if (searchClear) searchClear.style.display = currentQuery ? "block" : "none";
      currentPage = 1;
      render();
    });
  }

  if (searchClear) {
    searchClear.addEventListener("click", () => {
      searchInput.value = "";
      currentQuery = "";
      searchClear.style.display = "none";
      currentPage = 1;
      render();
      searchInput.focus();
    });
  }

  pills.forEach((pill) => {
    pill.addEventListener("click", () => {
      pills.forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      currentFilter = pill.dataset.filter || "all";
      currentPage = 1;
      render();
    });
  });

  if (perPageSelect) {
    perPageSelect.addEventListener("change", () => {
      currentPage = 1;
      render();
    });
  }

  // Первоначальный рендер
  render();
}

function initGroupsMemberSelector() {
  const memberSections = document.querySelectorAll(".group-members-section");
  if (!memberSections.length) return;

  memberSections.forEach((section) => {
    const form = section.closest("form");
    if (!form) return;

    const chips = Array.from(section.querySelectorAll(".member-chip"));
    const adButtons = Array.from(form.querySelectorAll(".btn-ad-group-select"));
    const searchInput = section.querySelector(".member-search-input");
    const btnSelectAll = section.querySelector(".btn-select-all");
    const btnClearAll = section.querySelector(".btn-clear-all");
    const counterNum = section.querySelector(".member-count-num");
    const nameInput = form.querySelector('input[name="name"]');

    function updateCounter() {
      let checkedCount = 0;
      chips.forEach((chip) => {
        const cb = chip.querySelector('input[name="members"]');
        if (cb && cb.checked) checkedCount++;
      });
      if (counterNum) counterNum.textContent = checkedCount;
    }

    function getMatchingChips(btn) {
      const needleCN = (btn.dataset.adGroupCn || "").toLowerCase().trim();
      const needleDN = (btn.dataset.adGroup || "").toLowerCase().trim();
      return chips.filter((chip) => {
        const groups = (chip.dataset.adGroups || "").toLowerCase();
        if (!groups) return false;
        const tokens = groups.split("|").map((t) => t.trim()).filter(Boolean);
        return tokens.some((t) => (needleCN && t === needleCN) || (needleDN && t === needleDN));
      });
    }

    function syncAdButtons() {
      adButtons.forEach((btn) => {
        const matching = getMatchingChips(btn);
        const total = matching.length;
        let checkedCount = 0;
        matching.forEach((chip) => {
          const cb = chip.querySelector('input[name="members"]');
          if (cb && cb.checked) checkedCount++;
        });

        // Бейдж с количеством пользователей в группе AD и статусом выбора
        let countBadge = btn.querySelector(".ad-group-count");
        if (!countBadge) {
          countBadge = document.createElement("span");
          countBadge.className = "ad-group-count";
          btn.querySelector(".select-chip-label")?.appendChild(countBadge);
        }

        const adName = btn.dataset.adGroupCn || btn.dataset.adGroup || "";
        if (total === 0) {
          countBadge.textContent = "0";
          btn.classList.remove("active", "partial");
          btn.title = `${adName} (нет синхронизированных пользователей в БД)`;
        } else if (checkedCount === total) {
          countBadge.textContent = `${total}/${total} ✓`;
          btn.classList.add("active");
          btn.classList.remove("partial");
          btn.title = `${adName} (все ${total} участников выбраны)`;
        } else if (checkedCount > 0) {
          countBadge.textContent = `${checkedCount}/${total}`;
          btn.classList.add("partial");
          btn.classList.remove("active");
          btn.title = `${adName} (выбрано ${checkedCount} из ${total} участников)`;
        } else {
          countBadge.textContent = `${total}`;
          btn.classList.remove("active", "partial");
          btn.title = `${adName} (всего ${total} участников в БД)`;
        }
      });
    }

    // Клик по кнопке группы Active Directory
    adButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const matching = getMatchingChips(btn);
        if (!matching.length) return;

        const allChecked = matching.every((chip) => {
          const cb = chip.querySelector('input[name="members"]');
          return cb && cb.checked;
        });

        matching.forEach((chip) => {
          const cb = chip.querySelector('input[name="members"]');
          if (cb) cb.checked = !allChecked;
        });

        // Если поле названия группы пустое и мы только что выбрали группу,
        // авто-подставляем имя AD группы
        if (nameInput && !nameInput.value.trim() && !allChecked) {
          nameInput.value = btn.dataset.adGroupCn || "";
        }

        updateCounter();
        syncAdButtons();
      });
    });

    // Чекбоксы участников
    chips.forEach((chip) => {
      const cb = chip.querySelector('input[name="members"]');
      if (cb) {
        cb.addEventListener("change", () => {
          updateCounter();
          syncAdButtons();
        });
      }
    });

    // Живой поиск участников
    if (searchInput) {
      searchInput.addEventListener("input", () => {
        const q = searchInput.value.toLowerCase().trim();
        chips.forEach((chip) => {
          if (!q) {
            chip.style.display = "";
            return;
          }
          const u = (chip.dataset.username || "").toLowerCase();
          const d = (chip.dataset.displayname || "").toLowerCase();
          const g = (chip.dataset.adGroups || "").toLowerCase();
          const match = u.includes(q) || d.includes(q) || g.includes(q);
          chip.style.display = match ? "" : "none";
        });
      });
    }

    // Кнопка «Выбрать всех»
    if (btnSelectAll) {
      btnSelectAll.addEventListener("click", () => {
        chips.forEach((chip) => {
          if (chip.style.display !== "none") {
            const cb = chip.querySelector('input[name="members"]');
            if (cb) cb.checked = true;
          }
        });
        updateCounter();
        syncAdButtons();
      });
    }

    // Кнопка «Снять всех»
    if (btnClearAll) {
      btnClearAll.addEventListener("click", () => {
        chips.forEach((chip) => {
          if (chip.style.display !== "none") {
            const cb = chip.querySelector('input[name="members"]');
            if (cb) cb.checked = false;
          }
        });
        updateCounter();
        syncAdButtons();
      });
    }

    // Первоначальная синхронизация
    updateCounter();
    syncAdButtons();
  });
}

// Панель настроек удаленной поддержки (категории и пороги телеметрии)
function initSupportSettingsPanel() {
  const supportPanel = document.getElementById("support-settings-panel");
  const btnToggleSupport = document.getElementById("btn-toggle-support-settings");
  const btnCloseSupport = document.getElementById("btn-close-support-settings");
  const btnAddCat = document.getElementById("btn-add-category-row");
  const catTbody = document.getElementById("categories-tbody");

  if (btnToggleSupport && supportPanel) {
    btnToggleSupport.addEventListener("click", () => {
      const isHidden = supportPanel.style.display === "none" || !supportPanel.style.display;
      supportPanel.style.display = isHidden ? "block" : "none";
      if (isHidden) {
        supportPanel.scrollIntoView({ behavior: "smooth" });
      }
    });
  }

  if (btnCloseSupport && supportPanel) {
    btnCloseSupport.addEventListener("click", () => {
      supportPanel.style.display = "none";
    });
  }

  if (btnAddCat && catTbody) {
    btnAddCat.addEventListener("click", () => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><input type="text" name="cat_id[]" class="input sm mono" required placeholder="например: buh"></td>
        <td><input type="text" name="cat_title[]" class="input sm" required placeholder="Бухгалтерия"></td>
        <td><input type="text" name="cat_icon[]" class="input sm" style="text-align: center;" value="💼"></td>
        <td><input type="text" name="cat_emails[]" class="input sm" placeholder="buh@corp.ru"></td>
        <td><input type="text" name="cat_telegram[]" class="input sm mono" placeholder="-100..."></td>
        <td style="text-align: center;"><button type="button" class="btn ghost sm danger cat-row-del" title="Удалить категорию">✕</button></td>
      `;
      catTbody.appendChild(tr);
    });
  }

  if (catTbody) {
    catTbody.addEventListener("click", (e) => {
      if (e.target && e.target.classList.contains("cat-row-del")) {
        const row = e.target.closest("tr");
        if (row && catTbody.querySelectorAll("tr").length > 1) {
          row.remove();
        } else {
          alert("Нельзя удалить единственную оставшуюся категорию.");
        }
      }
    });
  }
}

// Polling статуса Number Match push-челленджа на странице логина
function initNumberMatchPolling() {
  const matchCard = document.getElementById("number-match-box");
  if (!matchCard || !matchCard.dataset.challengeId) return;

  const chId = matchCard.dataset.challengeId;
  const pollInterval = 1500;
  const pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/v1/auth/challenge/${encodeURIComponent(chId)}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.status === "approved") {
        clearInterval(pollTimer);
        const statusEl = matchCard.querySelector(".number-match-status");
        if (statusEl) {
          statusEl.innerHTML = "✅ Подтверждено в приложении! Вход...";
          statusEl.style.color = "#10b981";
        }
        const actionInput = document.getElementById("login-action");
        const loginForm = document.getElementById("login-form");
        if (actionInput && loginForm) {
          actionInput.value = "push_claim";
          loginForm.submit();
        }
      } else if (data && (data.status === "denied" || data.status === "expired")) {
        clearInterval(pollTimer);
        const statusEl = matchCard.querySelector(".number-match-status");
        if (statusEl) {
          statusEl.innerHTML = data.status === "denied" ? "❌ Отклонено в приложении" : "⌛ Время ожидания истекло";
          statusEl.style.color = "#ef4444";
        }
      }
    } catch (_) {
      // сетевой retry
    }
  }, pollInterval);
}

// Быстрые шаблоны RADIUS Reply: кнопка data-radius-preset заполняет
// textarea[name="radius_reply"] своей формы (делигирование клика —
// покрывает кнопки, добавляемые после загрузки).
function initRadiusPresetButtons() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-radius-preset]");
    if (!btn) return;
    applyRadiusPreset(btn, btn.dataset.radiusPreset);
  });
}

function applyRadiusPreset(btn, preset) {
  const form = btn.closest('form');
  const textarea = form ? form.querySelector('textarea[name="radius_reply"]') : null;
  if (!textarea) return;
  const presets = {
    'mikrotik_std': '{\\n  "Mikrotik-Rate-Limit": "30M/50M"\\n}',
    'mikrotik_vip': '{\\n  "Mikrotik-Rate-Limit": "100M/100M",\\n  "Mikrotik-Group": "full"\\n}',
    'mikrotik_guest': '{\\n  "Mikrotik-Rate-Limit": "5M/10M",\\n  "Mikrotik-Address-List": "guest_users"\\n}',
    'unifi_vlan20': '{\\n  "Tunnel-Private-Group-Id": "20"\\n}',
    'unifi_vlan30': '{\\n  "Tunnel-Private-Group-Id": "30"\\n}',
    'workday': '{\\n  "Session-Timeout": "28800",\\n  "Idle-Timeout": "1800",\\n  "Port-Limit": "1"\\n}',
    'vpn_pool': '{\\n  "Framed-Pool": "vpn_users",\\n  "Session-Timeout": "28800"\\n}'
  };
  if (presets[preset]) {
    textarea.value = presets[preset].replace(/\\\\n/g, '\\n');
  }
}

// Селект профиля VLAN (data-vlan-input — id связанного текстового поля):
// выбор профиля подставляет номер VLAN в поле, «Свой номер...» —
// фокусирует его для ручного ввода.
function initVLANSelects() {
  document.addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-vlan-input]");
    if (!sel) return;
    const inp = document.getElementById(sel.dataset.vlanInput);
    if (!inp) return;
    if (sel.value !== "custom") {
      inp.value = sel.value;
    } else {
      inp.focus();
    }
  });
}

// Цвет аватара пользователя: значение приходит из шаблона (зависит от
// логина), поэтому применяется через CSSOM из data-атрибута.
function initUserAvatarColors() {
  for (const el of document.querySelectorAll(".user-avatar[data-avatar-bg]")) {
    if (el.dataset.avatarBg) {
      el.style.backgroundColor = el.dataset.avatarBg;
    }
  }
}

// Кнопка «⚡ Шаблон openidconnect.net» на странице OIDC-клиентов.
function initOIDCPlaygroundPreset() {
  const btn = document.getElementById("btn-preset-playground");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const name = document.getElementById("oidc-name");
    const uris = document.getElementById("oidc-redirect-uris");
    const cid = document.getElementById("oidc-client-id");
    const sec = document.getElementById("oidc-client-secret");
    const pub = document.getElementById("oidc-is-public");
    if (name) name.value = "openidconnect.net";
    if (uris) uris.value = "https://openidconnect.net/callback";
    if (cid) cid.value = "kbyuFDidLLm280LiWVfiazOqjO3ty8KH";
    if (sec) sec.value = "60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa";
    if (pub) pub.checked = false;
  });
}
