/* lua54.js — Analyseur de bytecode Lua 5.4 (lecture, désassemblage, arbre de prototypes).
   Format vérifié contre la source officielle Lua 5.4.9 (lundump.c / ldump.c / lopcodes.h).
   Fonctionne côté navigateur et sous Node (module UMD). */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Lua54 = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   * Jeu d'instructions (lopcodes.h, Lua 5.4)
   * ------------------------------------------------------------------ */
  var OPS = [
    ['MOVE', 'ABC'], ['LOADI', 'AsBx'], ['LOADF', 'AsBx'], ['LOADK', 'ABx'], ['LOADKX', 'ABC'],
    ['LOADFALSE', 'ABC'], ['LFALSESKIP', 'ABC'], ['LOADTRUE', 'ABC'], ['LOADNIL', 'ABC'],
    ['GETUPVAL', 'ABC'], ['SETUPVAL', 'ABC'],
    ['GETTABUP', 'ABC'], ['GETTABLE', 'ABC'], ['GETI', 'ABC'], ['GETFIELD', 'ABC'],
    ['SETTABUP', 'ABC'], ['SETTABLE', 'ABC'], ['SETI', 'ABC'], ['SETFIELD', 'ABC'],
    ['NEWTABLE', 'ABC'], ['SELF', 'ABC'],
    ['ADDI', 'ABC'], ['ADDK', 'ABC'], ['SUBK', 'ABC'], ['MULK', 'ABC'], ['MODK', 'ABC'],
    ['POWK', 'ABC'], ['DIVK', 'ABC'], ['IDIVK', 'ABC'], ['BANDK', 'ABC'], ['BORK', 'ABC'],
    ['BXORK', 'ABC'], ['SHRI', 'ABC'], ['SHLI', 'ABC'],
    ['ADD', 'ABC'], ['SUB', 'ABC'], ['MUL', 'ABC'], ['MOD', 'ABC'], ['POW', 'ABC'],
    ['DIV', 'ABC'], ['IDIV', 'ABC'], ['BAND', 'ABC'], ['BOR', 'ABC'], ['BXOR', 'ABC'],
    ['SHL', 'ABC'], ['SHR', 'ABC'],
    ['MMBIN', 'ABC'], ['MMBINI', 'ABC'], ['MMBINK', 'ABC'],
    ['UNM', 'ABC'], ['BNOT', 'ABC'], ['NOT', 'ABC'], ['LEN', 'ABC'], ['CONCAT', 'ABC'],
    ['CLOSE', 'ABC'], ['TBC', 'ABC'], ['JMP', 'sJ'],
    ['EQ', 'ABC'], ['LT', 'ABC'], ['LE', 'ABC'], ['EQK', 'ABC'], ['EQI', 'ABC'],
    ['LTI', 'ABC'], ['LEI', 'ABC'], ['GTI', 'ABC'], ['GEI', 'ABC'], ['TEST', 'ABC'],
    ['TESTSET', 'ABC'],
    ['CALL', 'ABC'], ['TAILCALL', 'ABC'], ['RETURN', 'ABC'], ['RETURN0', 'ABC'], ['RETURN1', 'ABC'],
    ['FORLOOP', 'ABx'], ['FORPREP', 'ABx'], ['TFORPREP', 'ABx'], ['TFORCALL', 'ABC'],
    ['TFORLOOP', 'ABx'],
    ['SETLIST', 'ABC'], ['CLOSURE', 'ABx'], ['VARARG', 'ABC'], ['VARARGPREP', 'ABC'],
    ['EXTRAARG', 'Ax']
  ];

  var OPCODES = OPS.map(function (o) { return o[0]; });
  var OPMODE = OPS.map(function (o) { return o[1]; });
  if (OPCODES.length !== 83) throw new Error('table d\'opcodes incomplète');

  /* Test d'une instruction (doit être suivie d'un saut) — bit 4 de luaP_opmodes */
  var TEST_OPS = {
    EQ: 1, LT: 1, LE: 1, EQK: 1, EQI: 1, LTI: 1, LEI: 1, GTI: 1, GEI: 1, TEST: 1, TESTSET: 1
  };

  var LUA_TAGS = { 0x00: 'nil', 0x01: 'false', 0x03: 'int', 0x11: 'true', 0x13: 'float', 0x04: 'string', 0x14: 'string' };

  /* ------------------------------------------------------------------ *
   * Lecture binaire
   * ------------------------------------------------------------------ */
  function Reader(bytes, littleEndian) {
    this.bytes = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.le = littleEndian !== false;
    this.p = 0;
  }
  Reader.prototype.need = function (n) {
    if (this.p + n > this.bytes.length) throw new Error('chunk tronqué : ' + n + ' octet(s) manquant(s) à l\'offset ' + this.p);
  };
  Reader.prototype.u8 = function () { this.need(1); return this.dv.getUint8(this.p++); };
  Reader.prototype.u32 = function () { this.need(4); var v = this.dv.getUint32(this.p, this.le); this.p += 4; return v; };
  Reader.prototype.i64 = function () { this.need(8); var v = this.dv.getBigInt64(this.p, this.le); this.p += 8; return Number(v); };
  Reader.prototype.f64 = function () { this.need(8); var v = this.dv.getFloat64(this.p, this.le); this.p += 8; return v; };
  Reader.prototype.take = function (n) {
    this.need(n);
    var out = this.bytes.subarray(this.p, this.p + n);
    this.p += n;
    return out;
  };
  /* Varint Lua 5.4 : base 128, octets de poids fort d'abord, dernier octet marqué 0x80 */
  Reader.prototype.varint = function () {
    var x = 0;
    for (var i = 0; i < 10; i++) {
      var b = this.u8();
      x = x * 128 + (b & 0x7f);
      if (b & 0x80) return x;
    }
    throw new Error('varint invalide à l\'offset ' + this.p);
  };
  Reader.prototype.luaString = function () {
    var n = this.varint();
    if (n === 0) return null;
    if (n > 64 * 1024 * 1024) throw new Error('taille de chaîne aberrante (' + n + ')');
    return this.take(n - 1);
  };

  /* ------------------------------------------------------------------ *
   * Chaînes
   * ------------------------------------------------------------------ */
  function decodeString(raw) {
    if (!raw) return null;
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(raw);
    } catch (e) {
      var s = '';
      for (var i = 0; i < raw.length; i++) s += String.fromCharCode(raw[i]);
      return s;
    }
  }
  function isPrintable(s) {
    if (!s) return false;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) return false;
      if (c === 127) return false;
    }
    return true;
  }

  function formatNumber(v) {
    if (typeof v !== 'number') return String(v);
    if (Number.isNaN(v)) return '(0/0)';
    if (v === Infinity) return '(1/0)';
    if (v === -Infinity) return '(-1/0)';
    if (Number.isInteger(v) && Object.is(v, Math.round(v)) && Math.abs(v) < 1e16) {
      return String(v);
    }
    var s = String(v);
    if (s.indexOf('.') === -1 && s.indexOf('e') === -1) s += '.0';
    return s;
  }

  function quoteLua(s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var ch = s[i], c = s.charCodeAt(i);
      if (ch === '\\') out += '\\\\';
      else if (ch === '"') out += '\\"';
      else if (ch === '\n') out += '\\n';
      else if (ch === '\r') out += '\\r';
      else if (ch === '\t') out += '\\t';
      else if (c < 32 || c === 127) out += '\\' + String(c).padStart(3, '0');
      else out += ch;
    }
    return out + '"';
  }

  /* ------------------------------------------------------------------ *
   * Décodage d'une instruction
   * ------------------------------------------------------------------ */
  function decodeInstruction(raw) {
    return {
      raw: raw >>> 0,
      op: raw & 0x7f,
      A: (raw >>> 7) & 0xff,
      k: (raw >>> 15) & 1,
      B: (raw >>> 16) & 0xff,
      C: (raw >>> 24) & 0xff,
      Bx: (raw >>> 15) & 0x1ffff,
      sBx: ((raw >>> 15) & 0x1ffff) - 65535,
      Ax: (raw >>> 7) & 0x1ffffff,
      sJ: ((raw >>> 7) & 0x1ffffff) - 16777215,
      sB: ((raw >>> 16) & 0xff) - 127,
      sC: ((raw >>> 24) & 0xff) - 127
    };
  }

  function instructionName(ins) {
    return OPCODES[ins.op] || ('OP?' + ins.op);
  }

  /* ------------------------------------------------------------------ *
   * Analyse du chunk
   * ------------------------------------------------------------------ */
  function parseChunk(input) {
    var bytes;
    if (input instanceof Uint8Array) bytes = input;
    else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
    else if (ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    else throw new Error('entrée invalide');

    if (bytes.length < 32) {
      var e0 = new Error('Fichier trop court pour être un chunk Lua (' + bytes.length + ' octets).');
      e0.code = 'TOO_SHORT';
      throw e0;
    }
    if (!(bytes[0] === 0x1b && bytes[1] === 0x4c && bytes[2] === 0x75 && bytes[3] === 0x61)) {
      var e1 = new Error('Ce fichier ne commence pas par la signature binaire Lua (\\x1bLua).');
      e1.code = 'NOT_BYTECODE';
      throw e1;
    }

    var version = bytes[4];
    var format = bytes[5];
    if (version !== 0x54) {
      var names = { 0x51: '5.1', 0x52: '5.2', 0x53: '5.3', 0x55: '5.5' };
      var e2 = new Error('Version de bytecode non prise en charge : ' + (names[version] || ('0x' + version.toString(16))) + ' (attendu : 5.4).');
      e2.code = 'BAD_VERSION';
      e2.version = version;
      throw e2;
    }
    if (format !== 0) {
      var e3 = new Error('Format de chunk inconnu (' + format + ') — attendu 0 pour du bytecode standard.');
      e3.code = 'BAD_FORMAT';
      throw e3;
    }
    var luacData = [bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]];
    var expected = [0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a];
    var dataOk = expected.every(function (b, i) { return luacData[i] === b; });

    var header = {
      version: '5.4',
      versionByte: version,
      format: format,
      luacDataOk: dataOk,
      instructionSize: bytes[12],
      integerSize: bytes[13],
      numberSize: bytes[14],
      littleEndian: true,
      luacInt: 0,
      luacNum: 0
    };

    var probe = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    header.luacInt = Number(probe.getBigInt64(15, true));
    if (header.luacInt !== 0x5678) {
      header.littleEndian = false;
      header.luacInt = Number(probe.getBigInt64(15, false));
    }
    header.luacNum = probe.getFloat64(23, header.littleEndian);

    if (header.luacInt !== 0x5678) {
      var e4 = new Error('En-tête incohérent : impossible de déterminer l\'ordre des octets.');
      e4.code = 'BAD_HEADER';
      throw e4;
    }
    if (header.instructionSize !== 4 || header.integerSize !== 8 || header.numberSize !== 8) {
      var e5 = new Error('Tailles de types non standard (instruction=' + header.instructionSize +
        ', integer=' + header.integerSize + ', number=' + header.numberSize + ').');
      e5.code = 'BAD_SIZES';
      throw e5;
    }

    var r = new Reader(bytes, header.littleEndian);
    r.p = 31;

    var warnings = [];
    function readProto(psource, depth) {
      if (depth > 200) throw new Error('profondeur de prototypes excessive');
      var proto = {
        source: null,
        sourceOwn: false,
        linedefined: 0,
        lastlinedefined: 0,
        numparams: 0,
        is_vararg: 0,
        maxstacksize: 0,
        code: [],
        constants: [],
        upvalues: [],
        protos: [],
        debug: { lineinfo: [], abslineinfo: [], locvars: [], upvalueNames: [] }
      };
      var srcBytes = r.luaString();
      if (srcBytes) {
        proto.source = decodeString(srcBytes);
        proto.sourceOwn = true;
      } else {
        proto.source = psource;
      }
      proto.linedefined = r.varint();
      proto.lastlinedefined = r.varint();
      proto.numparams = r.u8();
      proto.is_vararg = r.u8();
      proto.maxstacksize = r.u8();

      var ncode = r.varint();
      if (ncode < 0 || ncode > 4000000) throw new Error('nombre d\'instructions aberrant : ' + ncode);
      for (var i = 0; i < ncode; i++) proto.code.push(decodeInstruction(r.u32()));

      var nk = r.varint();
      if (nk < 0 || nk > 4000000) throw new Error('nombre de constantes aberrant : ' + nk);
      for (var j = 0; j < nk; j++) {
        var tag = r.u8();
        var t = LUA_TAGS[tag];
        if (t === 'nil') proto.constants.push({ type: 'nil', value: null });
        else if (t === 'false') proto.constants.push({ type: 'boolean', value: false });
        else if (t === 'true') proto.constants.push({ type: 'boolean', value: true });
        else if (t === 'int') proto.constants.push({ type: 'integer', value: r.i64() });
        else if (t === 'float') proto.constants.push({ type: 'float', value: r.f64() });
        else if (t === 'string') {
          var raw = r.luaString();
          var text = decodeString(raw);
          proto.constants.push({ type: 'string', value: text, raw: raw, printable: isPrintable(text) });
        } else {
          throw new Error('type de constante inconnu : 0x' + tag.toString(16) + ' (offset ' + r.p + ')');
        }
      }

      var nup = r.varint();
      if (nup < 0 || nup > 100000) throw new Error('nombre d\'upvalues aberrant : ' + nup);
      for (var u = 0; u < nup; u++) {
        proto.upvalues.push({ instack: r.u8(), idx: r.u8(), kind: r.u8(), name: null });
      }

      var np = r.varint();
      if (np < 0 || np > 100000) throw new Error('nombre de prototypes aberrant : ' + np);
      for (var p = 0; p < np; p++) proto.protos.push(readProto(proto.source, depth + 1));

      var nline = r.varint();
      if (nline > 0) {
        var li = r.take(nline);
        for (var l = 0; l < li.length; l++) proto.debug.lineinfo.push((li[l] << 24) >> 24);
      }
      var nabs = r.varint();
      for (var a = 0; a < nabs; a++) {
        proto.debug.abslineinfo.push({ pc: r.varint(), line: r.varint() });
      }
      var nloc = r.varint();
      if (nloc > 0 && nloc > ncode + 100000) throw new Error('table de variables locales aberrante : ' + nloc);
      for (var v = 0; v < nloc; v++) {
        var nameBytes = r.luaString();
        proto.debug.locvars.push({
          name: nameBytes ? decodeString(nameBytes) : null,
          startpc: r.varint(),
          endpc: r.varint()
        });
      }
      var nupn = r.varint();
      if (nupn !== 0) {
        for (var un = 0; un < proto.upvalues.length; un++) {
          var nb = r.luaString();
          proto.upvalues[un].name = nb ? decodeString(nb) : null;
        }
      }
      return proto;
    }

    var sizeupvalues = r.u8();
    var main = readProto(null, 0);
    if (main.upvalues.length !== sizeupvalues && sizeupvalues !== 0) {
      warnings.push('Nombre d\'upvalues déclaré dans l\'en-tête (' + sizeupvalues + ') différent de celui du prototype principal (' + main.upvalues.length + ').');
    }
    if (!dataOk) warnings.push('Bloc de contrôle LUAC_DATA altéré : le chunk a probablement été modifié à la main.');

    var trailing = bytes.length - r.p;
    if (trailing > 0) {
      warnings.push(trailing + ' octet(s) suivi(s) après la fin du chunk (données additionnelles, en-tête d\'obfuscation ou bourrage).');
    }

    return {
      header: header,
      main: main,
      warnings: warnings,
      bytesUsed: r.p,
      totalBytes: bytes.length,
      hasDebugInfo: main.debug.lineinfo.length > 0 || main.debug.locvars.length > 0
    };
  }

  /* ------------------------------------------------------------------ *
   * Arbre des prototypes
   * ------------------------------------------------------------------ */
  function walkProtos(proto, visit, path, depth) {
    path = path || 'main';
    depth = depth || 0;
    visit(proto, path, depth);
    for (var i = 0; i < proto.protos.length; i++) {
      walkProtos(proto.protos[i], visit, path + '.' + (i + 1), depth + 1);
    }
  }

  function countStats(proto) {
    var stats = { prototypes: 0, instructions: 0, constants: 0, strings: 0, upvalues: 0 };
    walkProtos(proto, function (p) {
      stats.prototypes++;
      stats.instructions += p.code.length;
      stats.constants += p.constants.length;
      stats.upvalues += p.upvalues.length;
      for (var i = 0; i < p.constants.length; i++) if (p.constants[i].type === 'string') stats.strings++;
    });
    return stats;
  }

  function functionName(proto, index) {
    return 'function<' + (proto.source || '?') + ':' + proto.linedefined + ',' + proto.lastlinedefined + '>';
  }

  /* ------------------------------------------------------------------ *
   * Désassemblage (style luac -l)
   * ------------------------------------------------------------------ */
  function operandText(proto, ins) {
    var name = instructionName(ins);
    var mode = OPMODE[ins.op];
    var parts = [];
    if (mode === 'ABx') parts = [ins.A, ins.Bx];
    else if (mode === 'AsBx') parts = [ins.A, ins.sBx];
    else if (mode === 'Ax') parts = [ins.Ax];
    else if (mode === 'sJ') parts = [ins.sJ];
    else {
      parts = [ins.A, ins.B, ins.C];
      if (ins.k) parts.push('k');
    }
    return parts.join(' ');
  }

  function commentFor(proto, ins, index) {
    var name = instructionName(ins);
    var k = proto.constants;
    function kText(i) {
      if (!k || k[i] === undefined) return 'K' + i;
      var c = k[i];
      if (c.type === 'string') return c.printable ? quoteLua(c.value) : 'K' + i + ' <binaire ' + (c.raw ? c.raw.length : 0) + 'o>';
      return formatNumber(c.value) === 'null' ? 'nil' : formatNumber(c.value);
    }
    switch (name) {
      case 'LOADK': case 'LOADKX': return kText(ins.Bx !== undefined && name === 'LOADK' ? ins.Bx : ins.Ax);
      case 'GETFIELD': case 'SETFIELD': return kText(ins.B);
      case 'GETTABUP': case 'SETTABUP': return kText(ins.B === undefined ? -1 : (name === 'SETTABUP' ? ins.B : ins.C));
      case 'EQK': return kText(ins.B);
      case 'ADDK': case 'SUBK': case 'MULK': case 'MODK': case 'POWK': case 'DIVK':
      case 'IDIVK': case 'BANDK': case 'BORK': case 'BXORK': case 'MMBINK':
        return kText(ins.C !== undefined && name !== 'MMBINK' ? ins.C : ins.B);
      case 'SELF': case 'GETTABLE': return ins.k ? kText(ins.C) : '';
      case 'SETTABLE': case 'SETI': return ins.k ? kText(ins.C) : '';
      case 'CLOSURE': return 'proto[' + ins.Bx + ']';
      default: return '';
    }
  }

  function disassemble(proto) {
    var lines = [];
    var functionIndex = 0;
    function dump(p, path) {
      lines.push('');
      var kind = path === 'main' ? 'fonction principale' : 'prototype ' + path;
      lines.push('-- ' + kind + '  source=' + (p.source || '?') + '  lignes ' + p.linedefined + '-' + p.lastlinedefined);
      lines.push('-- paramètres=' + p.numparams + '  vararg=' + (p.is_vararg ? 'oui' : 'non') +
        '  pile max=' + p.maxstacksize + '  instructions=' + p.code.length + '  upvalues=' + p.upvalues.length);
      lines.push('');
      var width = String(Math.max(0, p.code.length - 1)).length;
      for (var pc = 0; pc < p.code.length; pc++) {
        var ins = p.code[pc];
        var name = instructionName(ins);
        var lineNo = '';
        if (p.debug.lineinfo.length === p.code.length) {
          lineNo = p.debug.lineinfo[pc] + 1;
        }
        var pad = function (s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); };
        var row = pad(pc, width) + '  ' + pad(lineNo, 4) + '  ' + pad(name, 11) + ' ' + pad(operandText(p, ins), 12);
        var cm = commentFor(p, ins, pc);
        if (cm) row += ' ; ' + cm;
        lines.push(row.replace(/\s+$/, ''));
      }
      for (var i = 0; i < p.protos.length; i++) dump(p.protos[i], path + '.' + (i + 1));
    }
    dump(proto, 'main');
    return lines.join('\n');
  }

  return {
    OPCODES: OPCODES,
    TEST_OPS: TEST_OPS,
    decodeInstruction: decodeInstruction,
    instructionName: instructionName,
    parseChunk: parseChunk,
    disassemble: disassemble,
    walkProtos: walkProtos,
    countStats: countStats,
    functionName: functionName,
    formatNumber: formatNumber,
    quoteLua: quoteLua,
    decodeString: decodeString,
    isPrintable: isPrintable
  };
});
