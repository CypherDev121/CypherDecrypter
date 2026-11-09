/* deobf.js — Désobfuscation de code source Lua (chaînes encodées, base64, xor, string.char).
   S'applique à du code source lisible par un humain, pas à du bytecode chiffré. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Deobf = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var LUA_WORDS = [
    'local ', 'function', 'return', 'end', 'then', 'else', 'elseif', 'for ', 'while ', 'repeat',
    'until', 'break', 'self', 'nil', 'true', 'false', 'print(', 'table.', 'string.', 'math.',
    'RegisterNetEvent', 'AddEventHandler', 'TriggerServerEvent', 'TriggerClientEvent',
    'SetTimeout', 'CreateThread', 'GetEntityCoords', 'exports', 'source'
  ];

  function score(text) {
    var s = 0;
    var low = text.toLowerCase();
    for (var i = 0; i < LUA_WORDS.length; i++) {
      var w = LUA_WORDS[i].toLowerCase();
      var at = low.indexOf(w);
      while (at !== -1) {
        s += 3;
        at = low.indexOf(w, at + w.length);
      }
    }
    /* octets de contrôle : pénalité forte */
    var bad = 0;
    for (var j = 0; j < text.length; j++) {
      var c = text.charCodeAt(j);
      if ((c < 9 || (c > 13 && c < 32)) || c === 127) bad++;
    }
    s -= bad * 6;
    return s;
  }

  function printableRatio(text) {
    if (!text.length) return 0;
    var ok = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 160) ok++;
    }
    return ok / text.length;
  }

  function decodeBase64(s) {
    try {
      if (typeof atob === 'function') {
        var bin = atob(s);
        var out = '';
        for (var i = 0; i < bin.length; i++) out += String.fromCharCode(bin.charCodeAt(i));
        return out;
      }
      return Buffer.from(s, 'base64').toString('latin1');
    } catch (e) {
      return null;
    }
  }

  function xorSingle(text, key) {
    var out = '';
    for (var i = 0; i < text.length; i++) out += String.fromCharCode(text.charCodeAt(i) ^ key);
    return out;
  }

  function luaQuote(s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i), code = s.charCodeAt(i);
      if (c === '\\') out += '\\\\';
      else if (c === '"') out += '\\"';
      else if (c === '\n') out += '\\n';
      else if (c === '\r') out += '\\r';
      else if (c === '\t') out += '\\t';
      else if (code < 32 || code === 127) out += '\\' + String(code).padStart(3, '0');
      else out += c;
    }
    return out + '"';
  }

  /* --- 1. string.char(104, 101, 108) -> "hel" --- */
  function foldStringChar(src, log) {
    var count = 0;
    var out = src.replace(/string\.char\s*\(([0-9,\s]+)\)/g, function (all, nums) {
      var parts = nums.split(',').map(function (n) { return parseInt(n.trim(), 10); });
      if (parts.some(function (n) { return isNaN(n) || n < 0 || n > 255; })) return all;
      count++;
      return luaQuote(parts.map(function (n) { return String.fromCharCode(n); }).join(''));
    });
    if (count) log.push({ pass: 'string.char', detail: count + ' appel(s) replié(s) en littéraux' });
    return out;
  }

  /* --- 2. littéraux numériques hexadécimaux de caractères : \x41 et \065 --- */
  function foldEscapes(src, log) {
    var count = 0;
    var out = src.replace(/"((?:[^"\\]|\\.)*)"/g, function (all, body) {
      if (body.indexOf('\\') === -1) return all;
      var decoded = '';
      for (var i = 0; i < body.length; i++) {
        var c = body[i];
        if (c !== '\\') { decoded += c; continue; }
        var n = body[i + 1];
        if (n === 'n') { decoded += '\n'; i++; }
        else if (n === 't') { decoded += '\t'; i++; }
        else if (n === 'r') { decoded += '\r'; i++; }
        else if (n === '\\') { decoded += '\\'; i++; }
        else if (n === '"') { decoded += '"'; i++; }
        else if (n === 'x') {
          var hex = body.substr(i + 2, 2);
          if (/^[0-9a-fA-F]{2}$/.test(hex)) { decoded += String.fromCharCode(parseInt(hex, 16)); i += 3; }
          else decoded += c;
        } else if (/[0-9]/.test(n)) {
          var dec = body.substr(i + 1, 3).match(/^[0-9]{1,3}/)[0];
          decoded += String.fromCharCode(parseInt(dec, 10)); i += dec.length;
        } else { decoded += c; }
      }
      if (decoded === body.replace(/\\(.)/g, '$1')) return all;
      count++;
      return luaQuote(decoded);
    });
    if (count) log.push({ pass: 'séquences d\'échappement', detail: count + ' littéral(aux) décodé(s)' });
    return out;
  }

  /* --- 3. base64 / xor sur les longs littéraux --- */
  function decodeLiterals(src, log, depth) {
    var countB64 = 0, countXor = 0;
    var out = src.replace(/"([A-Za-z0-9+/=]{40,})"/g, function (all, body) {
      var decoded = decodeBase64(body);
      if (decoded && printableRatio(decoded) > 0.92 && score(decoded) > 6) {
        countB64++;
        log.push({
          pass: 'base64',
          detail: 'littéral de ' + body.length + ' caractères décodé (' + decoded.length + ' o, score Lua ' + score(decoded) + ')'
        });
        return luaQuote(decoded);
      }
      return all;
    });
    /* xor mono-octet : force brute + score */
    out = out.replace(/"([\x20-\x7e]{60,})"/g, function (all, body) {
      var best = null;
      for (var k = 1; k < 256; k++) {
        var cand = xorSingle(body, k);
        var sc = score(cand);
        if (!best || sc > best.sc) best = { sc: sc, k: k, text: cand };
      }
      if (best && best.sc > 24 && printableRatio(best.text) > 0.95) {
        countXor++;
        log.push({
          pass: 'xor mono-octet',
          detail: 'clé 0x' + best.k.toString(16).padStart(2, '0') + ' — score Lua ' + best.sc + ' sur ' + body.length + ' o'
        });
        return luaQuote(best.text);
      }
      return all;
    });
    if (countB64) log.push({ pass: 'base64', detail: countB64 + ' littéral(aux) décodé(s)' });
    if (countXor) log.push({ pass: 'xor mono-octet', detail: countXor + ' littéral(aux) déchiffré(s)' });
    return out;
  }

  /* --- 4. déballage load("...") / loadstring("...") --- */
  function unwrapLoad(src, log) {
    var re = /\b(?:load|loadstring)\s*\(\s*("(?:[^"\\]|\\.)*")\s*[,)]/;
    var m = re.exec(src);
    if (!m) return src;
    var inner;
    try {
      inner = JSON.parse(m[1].replace(/\\'/g, "'"));
    } catch (e) {
      return src;
    }
    if (typeof inner !== 'string' || inner.length < 20) return src;
    log.push({
      pass: 'déballage load()',
      detail: 'charge utile de ' + inner.length + ' caractères extraite'
    });
    return inner;
  }

  function deobfuscate(src, options) {
    options = options || {};
    var log = [];
    var text = String(src || '');
    var maxDepth = options.depth || 6;
    var changed = true;
    var round = 0;
    var current = text;

    while (changed && round < maxDepth) {
      changed = false;
      var before = current;
      current = foldStringChar(current, log);
      current = foldEscapes(current, log);
      current = decodeLiterals(current, log, round);
      current = unwrapLoad(current, log);
      if (current !== before) {
        changed = true;
        round++;
        log.push({ pass: 'passe ' + round, detail: 'nouvelle couche traitée' });
      }
    }

    if (!log.length) {
      log.push({ pass: 'aucune transformation', detail: 'rien d\'encodé de façon reconnaissable dans ce fichier' });
    }
    return { code: current, log: log, passes: round };
  }

  return { deobfuscate: deobfuscate, score: score, decodeBase64: decodeBase64, xorSingle: xorSingle };
});
