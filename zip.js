/* zip.js — lecteur ZIP minimal (méthode 0 = stocké, méthode 8 = deflate).
   Utilise DecompressionStream('deflate-raw') du navigateur, avec repli zlib sous Node. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Zip = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  function decodeName(bytes, from, to) {
    var s = '';
    for (var i = from; i < to; i++) s += String.fromCharCode(bytes[i]);
    try {
      var bin = '';
      for (var j = from; j < to; j++) bin += String.fromCharCode(bytes[j]);
      var arr = new Uint8Array(bin.length);
      for (var k = 0; k < bin.length; k++) arr[k] = bin.charCodeAt(k);
      return new TextDecoder('utf-8', { fatal: true }).decode(arr);
    } catch (e) {
      return s;
    }
  }

  function findEOCD(bytes) {
    var min = Math.max(0, bytes.length - 66000);
    for (var i = bytes.length - 22; i >= min; i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) return i;
    }
    return -1;
  }

  async function inflateRaw(data) {
    if (typeof DecompressionStream !== 'undefined') {
      try {
        var stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
        var buf = await new Response(stream).arrayBuffer();
        return new Uint8Array(buf);
      } catch (e) {
        /* on tente le repli */
      }
    }
    if (typeof require === 'function') {
      try {
        return new Uint8Array(require('zlib').inflateRawSync(data));
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  /* Liste les entrées d'une archive. Renvoie [{name, size, method, data}] */
  async function entries(bytes, options) {
    options = options || {};
    var maxEntries = options.maxEntries || 400;
    var maxSize = options.maxSize || 64 * 1024 * 1024;
    var out = [];
    var eocd = findEOCD(bytes);
    if (eocd < 0) return out;

    var total = u16(bytes, eocd + 10);
    var cdOffset = u32(bytes, eocd + 16);
    var ptr = cdOffset;

    for (var i = 0; i < total && i < maxEntries; i++) {
      if (ptr + 46 > bytes.length) break;
      if (!(bytes[ptr] === 0x50 && bytes[ptr + 1] === 0x4b && bytes[ptr + 2] === 0x01 && bytes[ptr + 3] === 0x02)) break;

      var method = u16(bytes, ptr + 10);
      var compSize = u32(bytes, ptr + 20);
      var uncompSize = u32(bytes, ptr + 24);
      var nameLen = u16(bytes, ptr + 28);
      var extraLen = u16(bytes, ptr + 30);
      var commentLen = u16(bytes, ptr + 32);
      var localOff = u32(bytes, ptr + 42);
      var name = decodeName(bytes, ptr + 46, ptr + 46 + nameLen);

      ptr += 46 + nameLen + extraLen + commentLen;

      if (/\/$/.test(name)) continue;
      if (compSize === 0xffffffff || uncompSize === 0xffffffff) {
        out.push({ name: name, size: 0, method: method, data: null, error: 'zip64 non pris en charge' });
        continue;
      }
      if (localOff + 30 > bytes.length) continue;

      var lnameLen = u16(bytes, localOff + 26);
      var lextraLen = u16(bytes, localOff + 28);
      var dataStart = localOff + 30 + lnameLen + lextraLen;
      if (dataStart + compSize > bytes.length) continue;

      var raw = bytes.subarray(dataStart, dataStart + compSize);
      var data = null;
      var error = null;

      if (method === 0) {
        data = raw;
      } else if (method === 8) {
        if (compSize > maxSize * 4 || uncompSize > maxSize) {
          error = 'entrée trop volumineuse';
        } else {
          data = await inflateRaw(raw);
          if (!data) error = 'décompression deflate indisponible';
        }
      } else {
        error = 'compression non gérée (méthode ' + method + ')';
      }

      out.push({ name: name, size: uncompSize, method: method, data: data, error: error });
    }

    return out;
  }

  function isZip(bytes) {
    return bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;
  }

  /* ------------------------------ écriture ------------------------------ */
  var CRC_TABLE = null;

  function crc32(bytes) {
    if (!CRC_TABLE) {
      CRC_TABLE = new Int32Array(256);
      for (var n = 0; n < 256; n++) {
        var c = n;
        for (var k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        CRC_TABLE[n] = c;
      }
    }
    var crc = -1;
    for (var i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ bytes[i]) & 0xff];
    return (crc ^ -1) >>> 0;
  }

  /* Écrit une archive non compressée (méthode 0), noms UTF-8, commentaire optionnel.
     files : [{ path, text }] ou [{ path, bytes }]. Renvoie un Uint8Array. */
  function create(files, options) {
    options = options || {};
    var enc = new TextEncoder();
    var comment = options.comment ? enc.encode(options.comment) : new Uint8Array(0);
    var now = options.date || new Date();
    var dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | Math.floor(now.getSeconds() / 2)) & 0xffff;
    var dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;

    var parts = [];
    var central = [];
    var offset = 0;

    files.forEach(function (f) {
      var nameBytes = enc.encode(f.path);
      var data = f.bytes || enc.encode(f.text == null ? '' : f.text);
      var crc = crc32(data);

      var local = new Uint8Array(30 + nameBytes.length);
      var p = 0;
      function w16(v) { local[p++] = v & 255; local[p++] = (v >>> 8) & 255; }
      function w32(v) { local[p++] = v & 255; local[p++] = (v >>> 8) & 255; local[p++] = (v >>> 16) & 255; local[p++] = (v >>> 24) & 255; }
      w32(0x04034b50); w16(20); w16(0x0800); w16(0); w16(dosTime); w16(dosDate);
      w32(crc); w32(data.length); w32(data.length); w16(nameBytes.length); w16(0);
      local.set(nameBytes, p);

      var cd = new Uint8Array(46 + nameBytes.length);
      var q = 0;
      function c16(v) { cd[q++] = v & 255; cd[q++] = (v >>> 8) & 255; }
      function c32(v) { cd[q++] = v & 255; cd[q++] = (v >>> 8) & 255; cd[q++] = (v >>> 16) & 255; cd[q++] = (v >>> 24) & 255; }
      c32(0x02014b50); c16(20); c16(20); c16(0x0800); c16(0); c16(dosTime); c16(dosDate);
      c32(crc); c32(data.length); c32(data.length); c16(nameBytes.length); c16(0); c16(0); c16(0); c16(0); c32(0); c32(offset);
      cd.set(nameBytes, q);

      parts.push(local, data);
      central.push(cd);
      offset += local.length + data.length;
    });

    var cdSize = central.reduce(function (n, c) { return n + c.length; }, 0);
    var eocd = new Uint8Array(22 + comment.length);
    var r = 0;
    function e16(v) { eocd[r++] = v & 255; eocd[r++] = (v >>> 8) & 255; }
    function e32(v) { eocd[r++] = v & 255; eocd[r++] = (v >>> 8) & 255; eocd[r++] = (v >>> 16) & 255; eocd[r++] = (v >>> 24) & 255; }
    e32(0x06054b50); e16(0); e16(0); e16(files.length); e16(files.length); e32(cdSize); e32(offset); e16(comment.length);
    eocd.set(comment, r);

    var out = new Uint8Array(offset + cdSize + eocd.length);
    var pos = 0;
    parts.forEach(function (part) { out.set(part, pos); pos += part.length; });
    central.forEach(function (c) { out.set(c, pos); pos += c.length; });
    out.set(eocd, pos);
    return out;
  }

  return { entries: entries, isZip: isZip, create: create, crc32: crc32 };
});
