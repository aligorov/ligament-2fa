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

  // Пример сопоставления групп AD с RADIUS-атрибутами: вставка готового JSON по кнопке.
  const groupExBtn = document.querySelector("[data-ldap-group-radius-example]");
  if (groupExBtn) {
    const area = document.querySelector('textarea[name="ldap.group_radius_map"]');
    groupExBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (area) {
        area.value = JSON.stringify({
          "VPN-Users": {
            "Filter-Id": "vpn_allow",
            "Mikrotik-Group": "vpn",
            "Session-Timeout": "28800"
          },
          "WiFi-Staff": {
            "Filter-Id": "staff_access",
            "Session-Timeout": "86400"
          }
        }, null, 2);
      }
    });
  }
});

