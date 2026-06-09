/* =========================================================================
   step-ui-ng — ui.js  (progressive enhancement only)
   The app is fully usable without this file:
     • copy buttons -> the value is plain selectable text / mono block
     • theme        -> falls back to prefers-color-scheme
   Nothing here is a framework; it is a few dozen lines of vanilla JS.
   The [data-theme] toggle is a REVIEW-MOCK affordance; the production app
   relies on prefers-color-scheme and can drop it entirely.
   ========================================================================= */
(function () {
  "use strict";

  /* ---- Copy to clipboard ------------------------------------------- */
  function flash(btn) {
    btn.classList.add("is-copied");
    window.setTimeout(function () { btn.classList.remove("is-copied"); }, 1400);
  }
  function copyText(text, btn) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { flash(btn); });
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); flash(btn); } catch (e) {}
      document.body.removeChild(ta);
    }
  }
  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".copy-btn");
    if (!btn) return;
    e.preventDefault();
    var text = btn.getAttribute("data-copy");
    if (text == null) {
      var sel = btn.getAttribute("data-copy-target");
      var el = sel && document.querySelector(sel);
      text = el ? (el.innerText || el.textContent) : "";
    }
    copyText(text || "", btn);
  });

  /* ---- PEM viewer expand/collapse ---------------------------------- */
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-pem-toggle]");
    if (!t) return;
    var pem = document.querySelector(t.getAttribute("data-pem-toggle"));
    if (!pem) return;
    var open = pem.classList.toggle("pem--open");
    t.textContent = open ? "Collapse" : "Expand";
  });

  /* ---- Theme toggle (review-mock affordance) ----------------------- */
  var root = document.documentElement;
  root.classList.add("js"); /* lets CSS know JS is available (mobile flat menu) */

  /* ---- Mobile: auto-expand the right-cluster menus into the flat panel.
     Genuinely toggles the `open` attribute (reliable sizing) instead of
     CSS-forcing a closed <details>. No-JS fallback = tappable disclosures. */
  var mq = window.matchMedia("(max-width: 900px)");
  function syncClusterMenus() {
    var mobile = mq.matches;
    document.querySelectorAll(".nav__panel .settings-menu, .nav__panel .mainmenu").forEach(function (d) {
      if (mobile) d.setAttribute("open", "");
      else d.removeAttribute("open");
    });
  }
  syncClusterMenus();
  if (mq.addEventListener) mq.addEventListener("change", syncClusterMenus);
  else if (mq.addListener) mq.addListener(syncClusterMenus);

  try {
    var saved = localStorage.getItem("stepui-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) {}

  function syncToggle() {
    var cur = root.getAttribute("data-theme") || "auto";
    document.querySelectorAll(".theme-toggle [data-theme-set]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-set") === cur));
    });
  }
  document.addEventListener("click", function (e) {
    var b = e.target.closest(".theme-toggle [data-theme-set]");
    if (!b) return;
    var mode = b.getAttribute("data-theme-set");
    try {
      if (mode === "auto") { root.removeAttribute("data-theme"); localStorage.removeItem("stepui-theme"); }
      else { root.setAttribute("data-theme", mode); localStorage.setItem("stepui-theme", mode); }
    } catch (err) {
      if (mode === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", mode);
    }
    syncToggle();
  });
  syncToggle();

  /* Close the mobile nav when a link is chosen (nicety) */
  document.addEventListener("click", function (e) {
    var link = e.target.closest(".nav__panel a");
    if (!link) return;
    if (window.matchMedia("(max-width: 900px)").matches) {
      var cb = document.getElementById("nav-toggle");
      if (cb) cb.checked = false;
    }
  });
})();
