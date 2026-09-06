// РСЯ (partner.yandex.ru): рендер всех блоков с data-rtb-block. Скрипт
// грузится только вместе с context.js и только на бесплатной лицензии;
// коллбек пушится в yandex_context_async_callbacks — context.js сам
// вызовет его после готовности Ya.Context.AdvManager.
"use strict";
document.querySelectorAll("[data-rtb-block]").forEach((el) => {
  const blockId = el.getAttribute("data-rtb-block");
  if (!blockId) return;
  window.yandex_context_async_callbacks =
    window.yandex_context_async_callbacks || [];
  window.yandex_context_async_callbacks.push(() => {
    if (window.Ya && window.Ya.Context && window.Ya.Context.AdvManager) {
      window.Ya.Context.AdvManager.render({
        blockId: blockId,
        renderTo: el.id,
      });
    }
  });
});
