// twofa: мелкие UI-улучшения без фреймворков: кнопки «Скопировать»
// (data-copy копирует текст соседнего code-элемента в буфер обмена) и
// выбор пресета SMS-шлюза в настройках (data-sms-preset).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
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
});
