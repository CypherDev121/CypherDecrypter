/* ------------------------------------------------------------------ *
 * island.js — pastille de verre animée façon « dynamic island ».
 * Elle reste un point lumineux discret, puis se déploie sur les
 * événements de l'interface (changement d'outil, archive générée…).
 * Purement décoratif : pointer-events désactivés, aucun texte injecté en HTML.
 * ------------------------------------------------------------------ */
(function (root) {
  'use strict';

  var el = null;
  var titleEl = null;
  var detailEl = null;
  var timer = 0;

  function build() {
    if (el) return;
    el = document.createElement('div');
    el.className = 'island';
    el.id = 'island';
    el.dataset.open = '0';
    el.dataset.tone = 'info';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');

    var dot = document.createElement('span');
    dot.className = 'island-dot';
    dot.setAttribute('aria-hidden', 'true');

    var body = document.createElement('div');
    body.className = 'island-body';

    titleEl = document.createElement('span');
    titleEl.className = 'island-title';
    detailEl = document.createElement('span');
    detailEl.className = 'island-detail';

    body.appendChild(titleEl);
    body.appendChild(detailEl);
    el.appendChild(dot);
    el.appendChild(body);
    document.body.appendChild(el);
  }

  function open(title, detail, tone) {
    if (!el) build();
    if (!el) return;
    titleEl.textContent = String(title || '');
    detailEl.textContent = String(detail || '');
    el.dataset.tone = tone || 'info';
    el.dataset.open = '1';
    clearTimeout(timer);
    timer = setTimeout(close, 3600);
  }

  function close() {
    if (!el) return;
    clearTimeout(timer);
    el.dataset.open = '0';
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || !t.closest) return;

    var tab = t.closest('.tab');
    if (tab) {
      open(tab.textContent.trim(), 'outil actif', 'info');
      return;
    }

    var dl = t.closest('a[download]');
    if (dl) {
      open('Archive prête', dl.getAttribute('download') || 'fichier téléchargé', 'ok');
    }
  }, true);

  document.addEventListener('cypher:island', function (e) {
    var d = (e && e.detail) || {};
    open(d.title, d.detail, d.tone);
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }

  root.Island = { notify: open, close: close };
})(typeof window !== 'undefined' ? window : globalThis);
