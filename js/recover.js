/* recover.js — Récupération de chunks Lua 5.4 depuis n'importe quel fichier.
   Chaîne : détection → décapsulage (préfixe, xor, base64, inversion, en-tête altéré)
   → validation → décompilation.  Plus déchiffrement AES avec une clé fournie.

   Ce que ce module ne fait pas : retrouver une clé. Un payload escrow FXAP est
   chiffré avec une clé dérivée côté plateforme ; sans elle, les octets restent
   indistinguables de données aléatoires. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Recover = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var MAX_SCAN = 16 * 1024 * 1024;
  var MAX_CANDIDATES = 40;

  function sigAt(b, i) {
    return b[i] === 0x1b && b[i + 1] === 0x4c && b[i + 2] === 0x75 && b[i + 3] === 0x61;
  }

  function scanSignatures(bytes, limit) {
    var out = [];
    var n = Math.min(bytes.length - 3, MAX_SCAN);
    for (var i = 0; i < n; i++) {
      if (sigAt(bytes, i)) {
        out.push(i);
        if (out.length >= (limit || 24)) break;
      }
    }
    return out;
  }

  /* En-tête canonique Lua 5.4 (31 octets), utilisé pour réparer un en-tête altéré. */
  function canonicalHeader() {
    var h = new Uint8Array(31);
    h[0] = 0x1b; h[1] = 0x4c; h[2] = 0x75; h[3] = 0x61;
    h[4] = 0x54; h[5] = 0x00;
    h[6] = 0x19; h[7] = 0x93; h[8] = 0x0d; h[9] = 0x0a; h[10] = 0x1a; h[11] = 0x0a;
    h[12] = 4; h[13] = 8; h[14] = 8;
    var dv = new DataView(h.buffer);
    dv.setBigInt64(15, BigInt(0x5678), true);
    dv.setFloat64(23, 370.5, true);
    return h;
  }

  function repairHeader(sub, bodySkip) {
    var skip = bodySkip || 31;
    if (sub.length <= skip) return null;
    var out = new Uint8Array(31 + (sub.length - skip));
    out.set(canonicalHeader(), 0);
    out.set(sub.subarray(skip), 31);
    return out;
  }

  function asciiOf(bytes, limit) {
    var n = Math.min(bytes.length, limit || 200000);
    var s = '';
    for (var i = 0; i < n; i++) {
      var c = bytes[i];
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '\u0000';
    }
    return s;
  }

  function b64ToBytes(s) {
    try {
      if (typeof atob === 'function') {
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      }
      var buf = Buffer.from(s, 'base64');
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (e) {
      return null;
    }
  }

  function hexToBytes(s) {
    var clean = String(s).replace(/[^0-9a-fA-F]/g, '');
    if (clean.length < 2 || clean.length % 2) return null;
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  /* Clé ou IV : hexadécimal avec préfixe, hexadécimal pur, ou base64. */
  function parseKey(text) {
    var s = String(text || '').trim();
    if (!s) return null;
    if (/^(0x)?[0-9a-fA-F]+$/.test(s) && s.replace(/^0x/, '').length % 2 === 0) {
      var h = hexToBytes(s);
      if (h) return h;
    }
    return b64ToBytes(s.replace(/\s+/g, ''));
  }

  function reverse(bytes) {
    var out = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
    return out;
  }

  function xorAll(bytes, key) {
    var out = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key;
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Analyse : liste des chunks récupérables
   * ------------------------------------------------------------------ */
  function analyze(bytes, Lua54, options) {
    options = options || {};
    var found = [];
    var seen = {};
    var notes = [];
    if (!Lua54) return { candidates: [], notes: ['module Lua54 absent'] };

    function add(transform, offset, data, extra) {
      if (!data || data.length < 32) return;
      if (found.length >= MAX_CANDIDATES) return;
      var fingerprint = transform + '|' + offset + '|' + data.length;
      if (seen[fingerprint]) return;
      seen[fingerprint] = 1;

      var parsed = null;
      var repaired = false;
      var error = null;
      var current = data;

      try {
        parsed = Lua54.parseChunk(current);
      } catch (e) {
        error = e;
        for (var skip = 31; skip <= 33 && !parsed; skip++) {
          var fixed = repairHeader(current, skip);
          if (!fixed) continue;
          try {
            parsed = Lua54.parseChunk(fixed);
            if (parsed) { current = fixed; repaired = true; }
          } catch (e2) { /* on continue */ }
        }
      }

      if (parsed) current = current.subarray(0, parsed.bytesUsed);

      found.push({
        transform: transform,
        offset: offset,
        size: current.length,
        data: current,
        parsed: parsed,
        repaired: repaired,
        error: parsed ? null : (error ? error.message : 'illisible'),
        note: extra || ''
      });
    }

    /* 1. chunks en clair, y compris imbriqués ou concaténés */
    scanSignatures(bytes, 24).forEach(function (off) {
      add('brut', off, bytes.subarray(off));
    });

    /* 2. xor mono-octet */
    var tried = 0;
    for (var k = 1; k < 256 && tried < 6; k++) {
      var hit = -1;
      var lim = Math.min(bytes.length - 4, 64);
      for (var i = 0; i <= lim; i++) {
        if ((bytes[i] ^ k) === 0x1b && (bytes[i + 1] ^ k) === 0x4c &&
            (bytes[i + 2] ^ k) === 0x75 && (bytes[i + 3] ^ k) === 0x61) { hit = i; break; }
      }
      if (hit < 0) continue;
      tried++;
      add('xor 0x' + k.toString(16).padStart(2, '0'), hit, xorAll(bytes, k).subarray(hit));
    }

    /* 3. octets inversés */
    var rev = reverse(bytes);
    scanSignatures(rev, 4).forEach(function (off) {
      add('octets inversés', off, rev.subarray(off));
    });

    /* 4. base64 et hexadécimal encapsulés */
    var ascii = asciiOf(bytes, 400000);
    var b64 = ascii.match(/[A-Za-z0-9+/]{200,}={0,2}/g) || [];
    b64.slice(0, 4).forEach(function (s) {
      var dec = b64ToBytes(s);
      if (!dec) return;
      scanSignatures(dec, 4).forEach(function (off) {
        add('base64', off, dec.subarray(off));
      });
      /* base64 → xor */
      for (var kk = 1; kk < 256; kk++) {
        if ((dec[0] ^ kk) !== 0x1b) continue;
        if ((dec[1] ^ kk) === 0x4c && (dec[2] ^ kk) === 0x75 && (dec[3] ^ kk) === 0x61) {
          add('base64 + xor 0x' + kk.toString(16).padStart(2, '0'), 0, xorAll(dec, kk));
          break;
        }
      }
    });

    var hexRuns = ascii.match(/(?:[0-9a-fA-F]{2}){200,}/g) || [];
    hexRuns.slice(0, 4).forEach(function (s) {
      var dec = hexToBytes(s);
      if (!dec) return;
      scanSignatures(dec, 4).forEach(function (off) {
        add('hexadécimal', off, dec.subarray(off));
      });
    });

    var ok = found.filter(function (c) { return c.parsed; });
    if (!ok.length) {
      notes.push('Aucun chunk Lua 5.4 exploitable après décapsulage. Le fichier est probablement chiffré (escrow) ou utilise un algorithme propriétaire.');
    }
    if (ok.some(function (c) { return c.repaired; })) {
      notes.push('Au moins un chunk avait un en-tête altéré : il a été reconstruit à partir d\'un en-tête canonique 5.4, puis relu avec succès.');
    }
    if (ok.some(function (c) { return /^xor/.test(c.transform); })) {
      notes.push('Un chunk chiffré par xor mono-octet a été récupéré : la clé est indiquée sur la carte correspondante.');
    }

    return { candidates: found, notes: notes };
  }

  /* ------------------------------------------------------------------ *
   * Déchiffrement AES avec une clé fournie
   * ------------------------------------------------------------------ */
  function payloadRegions(bytes) {
    var regions = [0];
    var head = Math.min(bytes.length, 4096);
    var marker = -1;
    for (var i = 0; i + 4 <= head; i++) {
      if (bytes[i] === 0x46 && bytes[i + 1] === 0x58 && bytes[i + 2] === 0x41 && bytes[i + 3] === 0x50) marker = i;
    }
    var anchor = marker >= 0 ? marker : 0;
    [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 64].forEach(function (d) {
      var r = anchor + d;
      if (r < bytes.length) regions.push(r);
    });
    if (marker >= 0) regions.push(marker);
    var clean = [];
    regions.forEach(function (r) {
      if (r >= 0 && r < bytes.length - 32 && clean.indexOf(r) === -1) clean.push(r);
    });
    return clean;
  }

  async function aesDecrypt(data, key, mode, iv) {
    var subtle = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle : null;
    if (!subtle) return { error: 'WebCrypto indisponible dans ce contexte' };
    var len = data.length - (data.length % 16);
    if (len < 64) return { data: null };
    var input = data.subarray(0, len);
    try {
      if (mode === 'ECB') {
        var ck = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
        var zero = new Uint8Array(16);
        var out = new Uint8Array(input.length);
        for (var off = 0; off < input.length; off += 16) {
          var blk = await subtle.decrypt({ name: 'AES-CBC', iv: zero }, ck, input.subarray(off, off + 16));
          out.set(new Uint8Array(blk), off);
        }
        return { data: out };
      }
      if (mode === 'CTR') {
        var ctrKey = await subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['decrypt']);
        var resCtr = await subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 64 }, ctrKey, input);
        return { data: new Uint8Array(resCtr) };
      }
      var cbKey = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
      var resCbc = await subtle.decrypt({ name: 'AES-CBC', iv: iv }, cbKey, input);
      return { data: new Uint8Array(resCbc) };
    } catch (e) {
      return { data: null, error: e.message };
    }
  }

  async function decrypt(bytes, options) {
    options = options || {};
    var Lua54 = options.lua || (typeof Lua54 !== 'undefined' ? Lua54 : null);
    var key = options.key;
    var mode = options.mode || 'CBC';
    if (!key || [16, 24, 32].indexOf(key.length) === -1) {
      return { ok: false, reason: 'clé invalide : 16, 24 ou 32 octets attendus' };
    }
    if (!Lua54) return { ok: false, reason: 'moteur Lua54 absent' };

    var attempts = [];
    var regions = payloadRegions(bytes);
    var ivList = [];
    if (options.iv && options.iv.length === 16) ivList.push({ label: 'IV fourni', iv: options.iv });
    ivList.push({ label: 'IV nul', iv: new Uint8Array(16) });

    for (var ri = 0; ri < regions.length; ri++) {
      var start = regions[ri];
      for (var vi = 0; vi < ivList.length; vi++) {
        attempts.push({ start: start, iv: ivList[vi].iv, label: ivList[vi].label });
        if (start + 16 < bytes.length) {
          attempts.push({
            start: start,
            iv: bytes.subarray(start, start + 16),
            label: 'IV = 16 premiers octets',
            bodySkip: 16
          });
        }
      }
    }

    var lastError = null;
    for (var a = 0; a < attempts.length; a++) {
      var at = attempts[a];
      var bodyStart = at.start + (at.bodySkip || 0);
      var payload = bytes.subarray(bodyStart);
      var res = await aesDecrypt(payload, key, mode, at.iv);
      if (!res || !res.data) {
        if (res && res.error) lastError = res.error;
        continue;
      }
      var plain = res.data;
      var hits = scanSignatures(plain, 4);
      for (var h = 0; h < hits.length; h++) {
        try {
          var parsed = Lua54.parseChunk(plain.subarray(hits[h]));
          return {
            ok: true,
            offset: bodyStart + hits[h],
            data: plain.subarray(hits[h], hits[h] + parsed.bytesUsed),
            parsed: parsed,
            mode: mode,
            ivLabel: at.label
          };
        } catch (e) {
          lastError = e.message;
        }
      }
    }

    return {
      ok: false,
      reason: 'aucune signature de chunk Lua trouvée dans le texte déchiffré' +
        (lastError ? ' (' + lastError + ')' : '')
    };
  }

  return {
    analyze: analyze,
    decrypt: decrypt,
    parseKey: parseKey,
    scanSignatures: scanSignatures,
    payloadRegions: payloadRegions
  };
});
