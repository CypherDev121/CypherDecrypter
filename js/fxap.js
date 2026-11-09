/* fxap.js — Analyse des conteneurs FiveM (escrow FXAP) et détection d'obfuscation.
   Tout se fait en mémoire, dans le navigateur. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Fxap = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var MARKERS = ['FXAP', 'fxap', 'escrow', 'ESCROW', 'cfx_', 'FiveM', 'fivem'];

  function ascii(bytes, from, to) {
    var s = '';
    for (var i = from; i < to; i++) {
      var c = bytes[i];
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }
    return s;
  }

  function shannon(bytes, from, to) {
    var counts = new Array(256).fill(0);
    var n = to - from;
    if (n <= 0) return 0;
    for (var i = from; i < to; i++) counts[bytes[i]]++;
    var h = 0;
    for (var j = 0; j < 256; j++) {
      if (!counts[j]) continue;
      var p = counts[j] / n;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function printableStrings(bytes, minLen, limit) {
    var out = [];
    var cur = '';
    var start = 0;
    for (var i = 0; i < bytes.length; i++) {
      var c = bytes[i];
      if (c >= 32 && c < 127) {
        if (!cur) start = i;
        cur += String.fromCharCode(c);
      } else {
        if (cur.length >= minLen) out.push({ value: cur, offset: start });
        cur = '';
        if (out.length >= limit) return out;
      }
    }
    if (cur.length >= minLen) out.push({ value: cur, offset: start });
    return out;
  }

  function findEmbeddedChunks(bytes) {
    var hits = [];
    for (var i = 0; i < bytes.length - 3; i++) {
      if (bytes[i] === 0x1b && bytes[i + 1] === 0x4c && bytes[i + 2] === 0x75 && bytes[i + 3] === 0x61) {
        hits.push(i);
        if (hits.length >= 20) break;
      }
    }
    return hits;
  }

  function base64Blobs(text) {
    var re = /[A-Za-z0-9+/]{120,}={0,2}/g;
    var m, out = [];
    while ((m = re.exec(text)) && out.length < 10) out.push({ length: m[0].length, sample: m[0].slice(0, 60) });
    return out;
  }

  function analyze(bytes, fileName) {
    var report = {
      fileName: fileName || 'fichier',
      size: bytes.length,
      verdict: 'inconnu',
      verdictLabel: '',
      entropy: 0,
      markers: [],
      strings: [],
      embeddedChunks: [],
      findings: [],
      isBytecode: false,
      preview: '',
      base64: []
    };

    report.preview = ascii(bytes, 0, Math.min(bytes.length, 320));
    report.isBytecode = bytes.length > 4 && bytes[0] === 0x1b && bytes[1] === 0x4c && bytes[2] === 0x75 && bytes[3] === 0x61;

    /* marqueurs dans les 8 premiers Ko */
    var head = ascii(bytes, 0, Math.min(bytes.length, 8192));
    MARKERS.forEach(function (m) {
      var at = head.indexOf(m);
      if (at !== -1) report.markers.push({ marker: m, offset: at });
    });

    report.embeddedChunks = findEmbeddedChunks(bytes);
    report.strings = printableStrings(bytes, 6, 300);
    report.base64 = base64Blobs(ascii(bytes, 0, Math.min(bytes.length, 200000)));

    var bodyStart = 0;
    if (report.markers.length) bodyStart = Math.min.apply(null, report.markers.map(function (m) { return m.offset; }));
    report.entropy = shannon(bytes, Math.min(bodyStart + 4, bytes.length), bytes.length);

    var hasFxap = report.markers.some(function (m) { return /fxap/i.test(m.marker); });

    if (report.isBytecode && !hasFxap) {
      report.verdict = 'bytecode';
      report.verdictLabel = 'Bytecode Lua standard — aucune protection de conteneur détectée';
      report.findings.push({
        level: 'ok',
        text: 'Signature \\x1bLua en position 0 : le fichier est un chunk Lua compilé classique, directement lisible.'
      });
    } else if (hasFxap) {
      report.verdict = 'fxap';
      report.verdictLabel = 'Conteneur FXAP (escrow) détecté';
      report.findings.push({
        level: 'warn',
        text: 'En-tête FXAP présent : le fichier a été protégé par le système d\'escrow de la plateforme. La charge utile est chiffrée et la clé est dérivée côté plateforme, jamais stockée dans le fichier.'
      });
    } else if (report.isBytecode === false && /function|local |return |load\(/.test(ascii(bytes, 0, Math.min(bytes.length, 4096)))) {
      report.verdict = 'source';
      report.verdictLabel = 'Code source Lua (non compilé)';
      report.findings.push({
        level: 'ok',
        text: 'Le fichier ressemble à du code source Lua lisible. Utilisez l\'onglet « Source obfusquée » pour nettoyer les chaînes encodées.'
      });
    } else {
      report.verdict = 'binaire';
      report.verdictLabel = 'Données binaires non identifiées';
      report.findings.push({
        level: 'warn',
        text: 'Ni signature Lua ni en-tête FXAP reconnu. Le fichier est peut-être encapsulé dans une couche personnalisée (xor, base64, archive).'
      });
    }

    if (report.entropy > 7.4 && report.size > 256) {
      report.findings.push({
        level: 'warn',
        text: 'Entropie de ' + report.entropy.toFixed(2) + ' bits/octet : la charge utile est indistinguable de données aléatoires, signature d\'un chiffrement ou d\'une compression.'
      });
    }
    if (report.embeddedChunks.length > 1) {
      report.findings.push({
        level: 'info',
        text: report.embeddedChunks.length + ' signatures de chunk Lua trouvées dans le fichier (offsets : ' +
          report.embeddedChunks.slice(0, 6).join(', ') + (report.embeddedChunks.length > 6 ? '…' : '') +
          '). Un chunk imbriqué peut être extrait tel quel.'
      });
    }
    if (report.base64.length) {
      report.findings.push({
        level: 'info',
        text: report.base64.length + ' bloc(s) base64 de plus de 120 caractères : chaîne probablement obfusquée en source, pas du bytecode.'
      });
    }

    var interesting = report.strings.filter(function (s) {
      return /ESCROW|FXAP|fxap|cfx|licen|key|token|http|\/\/|\.lua|lua5|Citizen|GetPlayer|RegisterNetEvent/i.test(s.value);
    });
    if (interesting.length) {
      report.findings.push({
        level: 'info',
        text: interesting.length + ' chaîne(s) textuelles remarquables extraites (noms d\'événements, chemins, identifiants de licence).'
      });
    }

    return report;
  }

  return { analyze: analyze, printableStrings: printableStrings, shannon: shannon };
});
