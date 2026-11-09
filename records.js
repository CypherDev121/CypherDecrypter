/* ------------------------------------------------------------------ *
 * records.js — classement local des sessions de nettoyage/déchiffrement.
 * Tout reste dans localStorage : aucun envoi, aucun compte, aucun serveur.
 * ------------------------------------------------------------------ */
(function (root) {
  'use strict';

  var KEY = 'cypherdecrypter.records.v1';
  var MAX = 60;

  var KINDS = {
    fxap: { label: 'Clean FXAP & Mapping', short: 'FXAP' },
    lua: { label: 'AntiCleanLUA', short: 'LUA' },
    nui: { label: 'AntiCleanNUI & LUA', short: 'NUI' },
    backdoor: { label: 'AntiCleanBackdoor', short: 'BD' }
  };

  /* Barème : une source récupérée pèse plus qu'un fichier simplement recopié,
     un conteneur chiffré traité plus qu'un fichier propre. */
  function scoreOf(e) {
    return Math.round(
      (e.files || 0) * 10 +
      (e.sources || 0) * 120 +
      (e.encrypted || 0) * 90 +
      (e.assets || 0) * 15 +
      (e.findings || 0) * 40
    );
  }

  function store() {
    try { return root.localStorage; } catch (err) { return null; }
  }

  function read() {
    var ls = store();
    if (!ls) return [];
    try {
      var raw = ls.getItem(KEY);
      if (!raw) return [];
      var list = JSON.parse(raw);
      return Array.isArray(list) ? list.filter(function (e) { return e && typeof e.score === 'number'; }) : [];
    } catch (err) {
      return [];
    }
  }

  function write(list) {
    var ls = store();
    if (!ls) return false;
    try { ls.setItem(KEY, JSON.stringify(list.slice(0, MAX))); return true; } catch (err) { return false; }
  }

  function list() {
    return read().sort(function (a, b) { return b.score - a.score || b.ts - a.ts; });
  }

  function add(entry) {
    var e = {
      ts: Date.now(),
      kind: KINDS[entry.kind] ? entry.kind : 'lua',
      label: String(entry.label || '').slice(0, 90) ||
        (KINDS[entry.kind] ? KINDS[entry.kind].label : 'Session'),
      files: entry.files || 0,
      sources: entry.sources || 0,
      encrypted: entry.encrypted || 0,
      assets: entry.assets || 0,
      findings: entry.findings || 0
    };
    e.score = scoreOf(e);
    if (!e.files && !e.sources && !e.assets) return null;

    var all = read();
    all.push(e);
    all.sort(function (a, b) { return b.score - a.score || b.ts - a.ts; });
    write(all.slice(0, MAX));
    if (typeof root.Records.onChange === 'function') root.Records.onChange();
    return e;
  }

  function totals() {
    return list().reduce(function (acc, e) {
      acc.score += e.score;
      acc.files += e.files;
      acc.sources += e.sources;
      acc.encrypted += e.encrypted;
      acc.assets += e.assets;
      acc.findings += e.findings;
      acc.runs += 1;
      return acc;
    }, { score: 0, files: 0, sources: 0, encrypted: 0, assets: 0, findings: 0, runs: 0 });
  }

  function best(kind) {
    var rows = kind ? list().filter(function (e) { return e.kind === kind; }) : list();
    return rows[0] || null;
  }

  function clear() {
    var ls = store();
    if (ls) { try { ls.removeItem(KEY); } catch (err) { /* mode privé */ } }
    if (typeof root.Records.onChange === 'function') root.Records.onChange();
  }

  function rank(score) {
    var rows = list();
    var at = rows.findIndex(function (e) { return e.score <= score; });
    return at === -1 ? rows.length + 1 : at + 1;
  }

  root.Records = {
    KEY: KEY,
    KINDS: KINDS,
    list: list,
    add: add,
    totals: totals,
    best: best,
    clear: clear,
    rank: rank,
    scoreOf: scoreOf,
    onChange: null
  };
})(typeof window !== 'undefined' ? window : globalThis);
