// twofa: мелкие UI-улучшения без фреймворков. Сейчас — кнопки «Скопировать»
// (data-copy копирует текст соседнего code-элемента в буфер обмена).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", async () => {
      const row = btn.closest(".copy-row");
      const src = row && row.querySelector("code, .linkcode");
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
});
