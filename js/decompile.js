/* decompile.js — Reconstruction de code source Lua 5.4 à partir du bytecode.
   Approche : simulation de registres + reconstruction structurée des sauts.
   Les zones non structurables sont émises en goto/étiquettes (valides en Lua 5.4). */
(function (root) {
  'use strict';

  function install(L) {
    var OPCODES = L.OPCODES, TEST_OPS = L.TEST_OPS, fmt = L.formatNumber, quote = L.quoteLua;

    var PREC = {
      'or': 1, 'and': 2,
      '==': 3, '~=': 3, '<': 3, '>': 3, '<=': 3, '>=': 3,
      '|': 4, '~': 5, '&': 6, '<<': 7, '>>': 7,
      '..': 8,
      '+': 9, '-': 9, '*': 10, '/': 10, '//': 10, '%': 10,
      unary: 11, '^': 12
    };
    var ATOM = 90;
    var KEYWORDS = {
      'and': 1, 'break': 1, 'do': 1, 'else': 1, 'elseif': 1, 'end': 1, 'false': 1, 'for': 1,
      'function': 1, 'goto': 1, 'if': 1, 'in': 1, 'local': 1, 'nil': 1, 'not': 1, 'or': 1,
      'repeat': 1, 'return': 1, 'then': 1, 'true': 1, 'until': 1, 'while': 1
    };
    var ARITH = {
      ADD: '+', SUB: '-', MUL: '*', MOD: '%', POW: '^', DIV: '/', IDIV: '//',
      BAND: '&', BOR: '|', BXOR: '~', SHL: '<<', SHR: '>>',
      ADDK: '+', SUBK: '-', MULK: '*', MODK: '%', POWK: '^', DIVK: '/', IDIVK: '//',
      BANDK: '&', BORK: '|', BXORK: '~', ADDI: '+'
    };
    var MM_AFTER = {
      ADD: 1, SUB: 1, MUL: 1, MOD: 1, POW: 1, DIV: 1, IDIV: 1, BAND: 1, BOR: 1,
      BXOR: 1, SHL: 1, SHR: 1, ADDI: 1, ADDK: 1, SUBK: 1, MULK: 1, MODK: 1, POWK: 1,
      DIVK: 1, IDIVK: 1, BANDK: 1, BORK: 1, BXORK: 1
    };
    var RIGHT_ASSOC = { '^': 1, '..': 1 };

    function ex(code, prec, extra) {
      var e = { code: code, prec: prec === undefined ? ATOM : prec };
      if (extra) for (var k in extra) e[k] = extra[k];
      return e;
    }

    function isIdent(s) {
      return typeof s === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(s) && !KEYWORDS[s];
    }

    /* Base d'un accès indexé : parenthèses si ce n'est pas un préfixe valide */
    function baseOf(e) {
      if (/^[A-Za-z_(]/.test(e.code)) return e.code;
      return '(' + e.code + ')';
    }

    function wrap(e, parentPrec, isRight, op) {
      var need = e.prec < parentPrec;
      if (!need && e.prec === parentPrec) {
        if (RIGHT_ASSOC[op]) need = !isRight;
        else need = isRight;
      }
      return need ? '(' + e.code + ')' : e.code;
    }

    function negate(code) {
      var m = /^not \((.*)\)$/.exec(code);
      if (m) return m[1];
      return 'not (' + code + ')';
    }

    /* ------------------------------------------------------------------ *
     * Comptage des lectures de registres : décide si une valeur est
     * intégrée dans l'expression ou matérialisée dans une variable.
     * ------------------------------------------------------------------ */
    function countRegReads(code, maxstack) {
      var counts = {};
      function inc(r) { if (r >= 0 && r < 256) counts[r] = (counts[r] || 0) + 1; }
      for (var pc = 0; pc < code.length; pc++) {
        var ins = code[pc];
        var op = OPCODES[ins.op];
        switch (op) {
          case 'MOVE': inc(ins.B); break;
          case 'GETTABLE': inc(ins.B); if (!ins.k) inc(ins.C); break;
          case 'GETI': case 'GETFIELD': inc(ins.B); break;
          case 'SETTABLE': inc(ins.A); inc(ins.B); if (!ins.k) inc(ins.C); break;
          case 'SETI': case 'SETFIELD': inc(ins.A); if (!ins.k) inc(ins.C); break;
          case 'SELF': inc(ins.B); if (!ins.k) inc(ins.C); break;
          case 'ADDI': case 'SHRI': case 'SHLI': case 'MMBINI':
            inc(ins.B); break;
          case 'ADDK': case 'SUBK': case 'MULK': case 'MODK': case 'POWK': case 'DIVK':
          case 'IDIVK': case 'BANDK': case 'BORK': case 'BXORK':
            inc(ins.B); break;
          case 'ADD': case 'SUB': case 'MUL': case 'MOD': case 'POW': case 'DIV': case 'IDIV':
          case 'BAND': case 'BOR': case 'BXOR': case 'SHL': case 'SHR': case 'MMBIN':
            inc(ins.B); inc(ins.C); break;
          case 'UNM': case 'BNOT': case 'NOT': case 'LEN': inc(ins.B); break;
          case 'CONCAT': for (var i = 0; i < ins.B; i++) inc(ins.A + i); break;
          case 'TEST': inc(ins.A); break;
          case 'TESTSET': inc(ins.B); break;
          case 'EQ': case 'LT': case 'LE': inc(ins.A); inc(ins.B); break;
          case 'EQK': case 'EQI': case 'LTI': case 'LEI': case 'GTI': case 'GEI': inc(ins.A); break;
          case 'CALL': case 'TAILCALL': {
            var n = ins.B === 0 ? maxstack : ins.B;
            for (var j = 0; j < n; j++) inc(ins.A + j);
            break;
          }
          case 'RETURN': {
            var m = ins.B === 0 ? maxstack : ins.B - 1;
            for (var q = 0; q < m; q++) inc(ins.A + q);
            break;
          }
          case 'RETURN1': inc(ins.A); break;
          case 'SETUPVAL': inc(ins.A); break;
          case 'FORPREP': inc(ins.A); inc(ins.A + 1); inc(ins.A + 2); break;
          case 'FORLOOP': inc(ins.A); inc(ins.A + 3); break;
          case 'TFORPREP': case 'TFORLOOP': inc(ins.A); inc(ins.A + 1); inc(ins.A + 2); break;
          case 'SETLIST': {
            inc(ins.A);
            var c = ins.B === 0 ? maxstack : ins.B;
            for (var s = 1; s <= c; s++) inc(ins.A + s);
            break;
          }
          default: break;
        }
      }
      return counts;
    }

    /* Registres lus par une instruction (pour l'analyse de vivacité) */
    function readRegsOf(ins, maxstack) {
      var op = OPCODES[ins.op], out = [];
      function add(r) { if (r >= 0 && r < 256) out.push(r); }
      switch (op) {
        case 'MOVE': add(ins.B); break;
        case 'GETTABLE': add(ins.B); if (!ins.k) add(ins.C); break;
        case 'GETI': case 'GETFIELD': add(ins.B); break;
        case 'SETTABLE': add(ins.A); add(ins.B); if (!ins.k) add(ins.C); break;
        case 'SETI': case 'SETFIELD': add(ins.A); if (!ins.k) add(ins.C); break;
        case 'SELF': add(ins.B); if (!ins.k) add(ins.C); break;
        case 'ADDI': case 'SHRI': case 'SHLI': add(ins.B); break;
        case 'ADDK': case 'SUBK': case 'MULK': case 'MODK': case 'POWK': case 'DIVK':
        case 'IDIVK': case 'BANDK': case 'BORK': case 'BXORK': add(ins.B); break;
        case 'ADD': case 'SUB': case 'MUL': case 'MOD': case 'POW': case 'DIV': case 'IDIV':
        case 'BAND': case 'BOR': case 'BXOR': case 'SHL': case 'SHR': case 'MMBIN':
          add(ins.B); add(ins.C); break;
        case 'UNM': case 'BNOT': case 'NOT': case 'LEN': add(ins.B); break;
        case 'CONCAT': for (var i = 0; i < ins.B; i++) add(ins.A + i); break;
        case 'TEST': add(ins.A); break;
        case 'TESTSET': add(ins.B); break;
        case 'EQ': case 'LT': case 'LE': add(ins.A); add(ins.B); break;
        case 'EQK': case 'EQI': case 'LTI': case 'LEI': case 'GTI': case 'GEI': add(ins.A); break;
        case 'CALL': case 'TAILCALL': {
          var n = ins.B === 0 ? maxstack : ins.B;
          for (var j = 0; j < n; j++) add(ins.A + j);
          break;
        }
        case 'RETURN': {
          var m = ins.B === 0 ? maxstack : ins.B - 1;
          for (var q = 0; q < m; q++) add(ins.A + q);
          break;
        }
        case 'RETURN1': add(ins.A); break;
        case 'SETUPVAL': add(ins.A); break;
        case 'FORPREP': add(ins.A); add(ins.A + 1); add(ins.A + 2); break;
        case 'FORLOOP': add(ins.A); add(ins.A + 3); break;
        case 'TFORPREP': case 'TFORLOOP': add(ins.A); add(ins.A + 1); add(ins.A + 2); break;
        case 'SETLIST': {
          add(ins.A);
          var c = ins.B === 0 ? maxstack : ins.B;
          for (var s = 1; s <= c; s++) add(ins.A + s);
          break;
        }
        default: break;
      }
      return out;
    }

    /* L'instruction écrit-elle dans ce registre ? */
    function writesRegTo(ins, reg) {
      var op = OPCODES[ins.op], A = ins.A;
      switch (op) {
        case 'MOVE': case 'LOADI': case 'LOADF': case 'LOADK': case 'LOADKX': case 'LOADFALSE':
        case 'LFALSESKIP': case 'LOADTRUE': case 'GETUPVAL': case 'GETTABUP': case 'GETTABLE':
        case 'GETI': case 'GETFIELD': case 'NEWTABLE': case 'ADDI': case 'ADDK': case 'SUBK':
        case 'MULK': case 'MODK': case 'POWK': case 'DIVK': case 'IDIVK': case 'BANDK':
        case 'BORK': case 'BXORK': case 'SHRI': case 'SHLI': case 'ADD': case 'SUB':
        case 'MUL': case 'MOD': case 'POW': case 'DIV': case 'IDIV': case 'BAND': case 'BOR':
        case 'BXOR': case 'SHL': case 'SHR': case 'UNM': case 'BNOT': case 'NOT': case 'LEN':
        case 'CONCAT': case 'CLOSURE': case 'VARARG': case 'TESTSET':
          return A === reg;
        case 'LOADNIL': return reg >= A && reg <= A + ins.B;
        case 'SELF': return reg === A || reg === A + 1;
        case 'CALL': {
          var c = ins.C === 0 ? 3 : ins.C - 1;
          return reg >= A && reg < A + Math.max(c, 1);
        }
        case 'FORLOOP': return reg === A || reg === A + 3;
        case 'FORPREP': return reg >= A && reg <= A + 2;
        case 'TFORCALL': return reg >= A + 4 && reg < A + 7;
        default: return false;
      }
    }

    /* ------------------------------------------------------------------ *
     * Émetteur par prototype
     * ------------------------------------------------------------------ */
    function FnEmitter(proto, options) {
      this.proto = proto;
      this.opts = options || {};
      this.lines = [];
      this.indent = 0;
      this.regs = [];
      this.tables = {};
      this.declared = {};
      this.selfCalls = {};
      this.lastCallInfo = null;
      this.warnings = this.opts.warnings || [];
      this.usedGoto = false;
      this.tempCounter = this.opts.tempCounter || { n: 0 };
      this.reads = countRegReads(proto.code, proto.maxstacksize);
      this.stmtSeq = 0;
      this.envUpvalue = this.findEnvUpvalue();
    }

    FnEmitter.prototype.findEnvUpvalue = function () {
      var ups = this.proto.upvalues || [];
      for (var i = 0; i < ups.length; i++) if (ups[i].name === '_ENV') return i;
      return -1;
    };

    /* Les noms entre parenthèses sont des variables internes du compilateur
       ((for state), (for generator)...) : on ne les expose pas. */
    function usableName(n) {
      return n && n.charAt(0) !== '(' ? n : null;
    }

    FnEmitter.prototype.localName = function (reg, pc) {
      var lv = this.proto.debug.locvars || [];
      if (!lv.length) return null;
      var idx = 0;
      for (var i = 0; i < lv.length; i++) {
        var v = lv[i];
        if (pc >= v.startpc && pc < v.endpc) {
          if (idx === reg) return usableName(v.name);
          idx++;
        }
      }
      return null;
    };

    /* Nom d'une variable déclarée juste après l'instruction courante */
    FnEmitter.prototype.declName = function (reg, pc) {
      var lv = this.proto.debug.locvars || [];
      if (!lv.length) return null;
      var active = 0, i;
      for (i = 0; i < lv.length; i++) {
        var v = lv[i];
        if (pc >= v.startpc && pc < v.endpc) active++;
      }
      var n = 0;
      for (i = 0; i < lv.length; i++) {
        var w = lv[i];
        if (w.startpc === pc + 1 && w.endpc > pc + 1) {
          if (active + n === reg) return usableName(w.name);
          n++;
        }
      }
      return null;
    };

    /* Nom disponible dans les instructions voisines (variables de boucle) */
    FnEmitter.prototype.nameNear = function (reg, pc) {
      for (var d = 0; d <= 4; d++) {
        var n = this.localName(reg, pc + d);
        if (n) return n;
      }
      return null;
    };

    FnEmitter.prototype.upvalueName = function (i) {
      var uv = this.proto.upvalues[i];
      if (uv && uv.name) return uv.name;
      return 'up' + (i + 1);
    };

    FnEmitter.prototype.konst = function (i) {
      var c = this.proto.constants[i];
      if (!c) return 'K' + i;
      if (c.type === 'string') return c.value === null ? '""' : quote(c.value);
      if (c.type === 'nil') return 'nil';
      if (c.type === 'boolean') return c.value ? 'true' : 'false';
      return fmt(c.value);
    };

    FnEmitter.prototype.konstKey = function (i) {
      var c = this.proto.constants[i];
      if (c && c.type === 'string' && isIdent(c.value)) return { access: '.' + c.value, item: c.value };
      return { access: '[' + this.konst(i) + ']', item: '[' + this.konst(i) + ']' };
    };

    FnEmitter.prototype.emit = function (text) {
      if (text === null || text === undefined) return;
      var pad = '  '.repeat(this.indent);
      var parts = String(text).split('\n');
      this.stmtSeq++;
      for (var i = 0; i < parts.length; i++) this.lines.push(parts[i].length ? pad + parts[i] : '');
    };

    FnEmitter.prototype.temp = function () {
      this.tempCounter.n++;
      return 't' + this.tempCounter.n;
    };

    /* Combien de fois la valeur présente dans un registre est-elle lue
       avant d'être écrasée ? 0/1 -> intégration dans l'expression. */
    FnEmitter.prototype.usesBeforeClobber = function (reg, pc) {
      var code = this.proto.code, count = 0;
      for (var i = pc + 1; i < code.length && i < pc + 500; i++) {
        var reads = readRegsOf(code[i], this.proto.maxstacksize);
        for (var k = 0; k < reads.length; k++) {
          if (reads[k] === reg) { count++; break; }
        }
        if (count > 1) return count;
        if (writesRegTo(code[i], reg)) break;
      }
      return count;
    };

    /* --- tables en construction --- */
    FnEmitter.prototype.flushTable = function (reg, pc) {
      var t = this.tables[reg];
      if (!t) return;
      delete this.tables[reg];
      var text = t.items.length ? '{ ' + t.items.join(', ') + ' }' : '{}';
      if (pc === undefined) { this.regs[reg] = ex(text, ATOM); return; }
      this.setExpr(reg, ex(text, ATOM), pc);
    };

    FnEmitter.prototype.flushAllTables = function (pc) {
      var self = this;
      Object.keys(this.tables).forEach(function (k) {
        var reg = Number(k);
        var t = self.tables[reg];
        delete self.tables[reg];
        var text = t.items.length ? '{ ' + t.items.join(', ') + ' }' : '{}';
        self.setExpr(reg, ex(text, ATOM, { materialize: true }), pc === undefined ? 0 : pc);
      });
    };

    /* --- lectures --- */
    FnEmitter.prototype.readRegExpr = function (reg, pc) {
      this.flushTable(reg, pc);
      var v = this.regs[reg];
      if (v && v.code) return v;
      var name = this.localName(reg, pc);
      return ex(name || ('v' + (reg + 1)), ATOM);
    };

    FnEmitter.prototype.regOrConst = function (reg, pc, isK) {
      if (isK) return ex(this.konst(reg), ATOM);
      return this.readRegExpr(reg, pc);
    };

    /* --- écritures --- */
    FnEmitter.prototype.setExpr = function (reg, exprObj, pc) {
      this.flushTable(reg, pc);
      var name = this.localName(reg, pc) || this.declName(reg, pc);
      if (name) {
        var isDecl = !this.declared[reg] || this.declName(reg, pc) === name;
        this.emit((isDecl ? 'local ' : '') + name + ' = ' + exprObj.code);
        this.declared[reg] = true;
        this.regs[reg] = ex(name, ATOM);
        return;
      }
      var times = this.usesBeforeClobber(reg, pc);
      if (exprObj.callSeq !== undefined && exprObj.callSeq !== this.stmtSeq) times = Math.max(times, 2);
      var tooBig = exprObj.code.length > 160;
      if (exprObj.materialize || times > 1 || tooBig) {
        var t = this.temp();
        this.emit('local ' + t + ' = ' + exprObj.code);
        this.declared[reg] = true;
        this.regs[reg] = ex(t, ATOM);
        return;
      }
      this.regs[reg] = exprObj;
    };

    /* ------------------------------------------------------------------ *
     * Conditions
     * ------------------------------------------------------------------ */
    FnEmitter.prototype.testCondition = function (pc) {
      var ins = this.proto.code[pc];
      var name = OPCODES[ins.op];
      var a = this.readRegExpr(ins.A, pc).code;
      switch (name) {
        case 'EQ': return a + ' == ' + this.readRegExpr(ins.B, pc).code;
        case 'LT': return a + ' < ' + this.readRegExpr(ins.B, pc).code;
        case 'LE': return a + ' <= ' + this.readRegExpr(ins.B, pc).code;
        case 'EQK': return a + ' == ' + this.konst(ins.B);
        case 'EQI': return a + ' == ' + fmt(ins.sB);
        case 'LTI': return a + ' < ' + fmt(ins.sB);
        case 'LEI': return a + ' <= ' + fmt(ins.sB);
        case 'GTI': return a + ' > ' + fmt(ins.sB);
        case 'GEI': return a + ' >= ' + fmt(ins.sB);
        case 'TEST': return a;
        case 'TESTSET': return this.readRegExpr(ins.B, pc).code;
        default: return 'true';
      }
    };

    FnEmitter.prototype.bodyCondition = function (pc) {
      var ins = this.proto.code[pc];
      var cond = this.testCondition(pc);
      return ins.k ? negate(cond) : cond;
    };

    FnEmitter.prototype.findRepeatEnd = function (start, end) {
      var code = this.proto.code;
      for (var i = start; i + 1 < end; i++) {
        var name = OPCODES[code[i].op];
        if (!TEST_OPS[name]) continue;
        var jmp = code[i + 1];
        if (OPCODES[jmp.op] !== 'JMP') return -1;
        return (i + 2 + jmp.sJ === start) ? i : -1;
      }
      return -1;
    };

    FnEmitter.prototype.emitGoto = function (target, why) {
      this.usedGoto = true;
      this.emit('goto L' + target + ' -- ' + why);
    };

    /* ------------------------------------------------------------------ *
     * Boucle principale
     * ------------------------------------------------------------------ */
    FnEmitter.prototype.emitRange = function (start, end, depth) {
      var code = this.proto.code;
      depth = depth || 0;
      if (depth > 60) {
        this.emit('-- [!] profondeur maximale de blocs atteinte (pc ' + start + ')');
        return;
      }
      var pc = start;

      while (pc < end) {
        /* répétition : test suivi d'un saut arrière vers le début du bloc */
        var repEnd = this.findRepeatEnd(pc, end);
        if (repEnd >= pc) {
          var rIns = code[repEnd];
          var rCond = this.testCondition(repEnd);
          var cont = rIns.k ? rCond : negate(rCond);
          this.emit('repeat');
          this.indent++;
          this.emitRange(pc, repEnd, depth + 1);
          this.indent--;
          this.emit('until ' + negate(cont));
          pc = repEnd + 2;
          continue;
        }

        var ins = code[pc];
        var op = OPCODES[ins.op];
        var A = ins.A, B = ins.B, C = ins.C;

        /* ---- structures de contrôle ---- */
        if (TEST_OPS[op] && pc + 1 < end && OPCODES[code[pc + 1].op] === 'JMP') {
          var jmp = code[pc + 1];
          var target = pc + 2 + jmp.sJ;
          if (target > pc + 1 && target <= end) {
            var bodyCond = this.bodyCondition(pc);
            var before = target - 1;
            var beforeOp = before > pc + 1 ? OPCODES[code[before].op] : null;
            var backTarget = beforeOp === 'JMP' ? target + code[before].sJ : null;
            if (backTarget === pc && before > pc + 1) {
              this.emit('while ' + bodyCond + ' do');
              this.indent++;
              this.withScope(function (self) { self.emitRange(pc + 2, before, depth + 1); });
              this.indent--;
              this.emit('end');
              pc = target;
              continue;
            }
            if (beforeOp === 'JMP' && backTarget > target) {
              this.emit('if ' + bodyCond + ' then');
              this.indent++;
              this.withScope(function (self) { self.emitRange(pc + 2, before, depth + 1); });
              this.indent--;
              this.emit('else');
              this.indent++;
              this.withScope(function (self) { self.emitRange(target, backTarget, depth + 1); });
              this.indent--;
              this.emit('end');
              pc = backTarget;
              continue;
            }
            if (target === pc + 2) { pc = target; continue; }
            this.emit('if ' + bodyCond + ' then');
            this.indent++;
            this.withScope(function (self) { self.emitRange(pc + 2, target, depth + 1); });
            this.indent--;
            this.emit('end');
            pc = target;
            continue;
          }
          this.emitGoto(target, 'condition pc ' + pc);
          pc += 2;
          continue;
        }

        switch (op) {
          case 'VARARGPREP': case 'CLOSE': case 'TBC': case 'EXTRAARG':
            pc++; continue;

          case 'MOVE': {
            var mv = this.readRegExpr(B, pc);
            this.setExpr(A, mv, pc);
            pc++; continue;
          }

          case 'LOADI': this.setExpr(A, ex(fmt(ins.sBx)), pc); pc++; continue;
          case 'LOADF': this.setExpr(A, ex(fmt(ins.sBx) + '.0'), pc); pc++; continue;
          case 'LOADK': this.setExpr(A, ex(this.konst(ins.Bx)), pc); pc++; continue;
          case 'LOADKX': {
            var extra = code[pc + 1];
            this.setExpr(A, ex(extra ? this.konst(extra.Ax) : 'nil'), pc);
            pc += 2; continue;
          }
          case 'LOADFALSE': this.setExpr(A, ex('false'), pc); pc++; continue;
          case 'LOADTRUE': this.setExpr(A, ex('true'), pc); pc++; continue;
          case 'LOADNIL':
            for (var n = 0; n <= B; n++) this.setExpr(A + n, ex('nil'), pc);
            pc++; continue;

          case 'LFALSESKIP': {
            if (code[pc + 1] && OPCODES[code[pc + 1].op] === 'LOADTRUE' && code[pc + 1].A === A) {
              var cnd = this.lastCond || 'false';
              this.setExpr(A, ex('(' + cnd + ')', PREC['==']), pc);
              delete this.lastCond;
              pc += 2; continue;
            }
            this.setExpr(A, ex('false'), pc);
            pc += 2; continue;
          }

          case 'GETUPVAL':
            this.setExpr(A, ex(this.upvalueName(B), ATOM), pc); pc++; continue;
          case 'SETUPVAL':
            this.emit(this.upvalueName(B) + ' = ' + this.readRegExpr(A, pc).code);
            pc++; continue;

          case 'GETTABUP': {
            var kConstT = this.proto.constants[C];
            var keyT = this.konstKey(C);
            var base = (this.envUpvalue !== -1 && B === this.envUpvalue) ? null : this.upvalueName(B);
            var globalCode;
            if (base) globalCode = base + keyT.access;
            else if (kConstT && kConstT.type === 'string' && isIdent(kConstT.value)) globalCode = kConstT.value;
            else globalCode = '_ENV' + keyT.access;
            this.setExpr(A, ex(globalCode, ATOM), pc);
            pc++; continue;
          }
          case 'GETTABLE': {
            var t1 = this.readRegExpr(B, pc);
            var k1 = this.regOrConst(C, pc, ins.k);
            this.setExpr(A, ex(baseOf(t1) + '[' + k1.code + ']', ATOM), pc);
            pc++; continue;
          }
          case 'GETI': {
            var t2 = this.readRegExpr(B, pc);
            this.setExpr(A, ex(baseOf(t2) + '[' + C + ']', ATOM), pc);
            pc++; continue;
          }
          case 'GETFIELD': {
            var t3 = this.readRegExpr(B, pc);
            this.setExpr(A, ex(baseOf(t3) + this.konstKey(C).access, ATOM), pc);
            pc++; continue;
          }

          case 'SETTABUP': {
            var isEnv = this.envUpvalue !== -1 && A === this.envUpvalue;
            var keyName = this.proto.constants[B];
            var keyS = this.konstKey(B).access;
            var valS = this.readRegExpr(C, pc).code;
            var leftS;
            if (!isEnv) leftS = this.upvalueName(A) + keyS;
            else if (keyName && keyName.type === 'string' && isIdent(keyName.value)) leftS = keyName.value;
            else leftS = '_ENV' + keyS;
            this.emit(leftS + ' = ' + valS);
            pc++; continue;
          }
          case 'SETTABLE': {
            var tk = this.readRegExpr(A, pc);
            var kk = this.readRegExpr(B, pc);
            var vv = this.regOrConst(C, pc, ins.k);
            if (this.tables[A]) { this.tables[A].items.push('[' + kk.code + '] = ' + vv.code); pc++; continue; }
            this.emit(tk.code + '[' + kk.code + '] = ' + vv.code);
            pc++; continue;
          }
          case 'SETI': {
            var ti = this.readRegExpr(A, pc);
            var vi = this.regOrConst(C, pc, ins.k);
            if (this.tables[A]) { this.tables[A].items[C - 1] = vi.code; pc++; continue; }
            this.emit(ti.code + '[' + B + '] = ' + vi.code);
            pc++; continue;
          }
          case 'SETFIELD': {
            var vf = this.regOrConst(C, pc, ins.k);
            var fk = this.konstKey(B);
            if (this.tables[A]) {
              this.tables[A].items.push(fk.item + ' = ' + vf.code);
              pc++; continue;
            }
            var tf = this.readRegExpr(A, pc);
            this.emit(tf.code + fk.access + ' = ' + vf.code);
            pc++; continue;
          }

          case 'NEWTABLE': {
            this.flushTable(A);
            this.tables[A] = { items: [] };
            this.regs[A] = null;
            pc++; continue;
          }

          case 'SELF': {
            var recv = baseOf(this.readRegExpr(B, pc));
            var mc = this.proto.constants[C];
            var mkey = ins.k ? this.konst(C) : this.readRegExpr(C, pc).code;
            var mIdent = (mc && mc.type === 'string' && isIdent(mc.value)) ? mc.value : null;
            this.selfCalls[A] = { recv: recv, name: mkey, ident: mIdent };
            this.regs[A] = ex(recv, ATOM);
            pc++; continue;
          }

          case 'ADDI': case 'ADDK': case 'SUBK': case 'MULK': case 'MODK': case 'POWK':
          case 'DIVK': case 'IDIVK': case 'BANDK': case 'BORK': case 'BXORK':
          case 'ADD': case 'SUB': case 'MUL': case 'MOD': case 'POW': case 'DIV': case 'IDIV':
          case 'BAND': case 'BOR': case 'BXOR': case 'SHL': case 'SHR': {
            var sym = ARITH[op];
            var leftE, rightE;
            if (op === 'ADDI') { leftE = this.readRegExpr(B, pc); rightE = ex(fmt(ins.sC)); }
            else if (/K$/.test(op)) { leftE = this.readRegExpr(B, pc); rightE = ex(this.konst(C)); }
            else { leftE = this.readRegExpr(B, pc); rightE = this.readRegExpr(C, pc); }
            var p = PREC[sym];
            var isRight = !!RIGHT_ASSOC[sym];
            var codeBin;
            if (sym === '+' && /^-(\d|\.)/.test(rightE.code)) {
              p = PREC['-'];
              codeBin = wrap(leftE, p, false, '-') + ' - ' + rightE.code.slice(1);
            } else {
              codeBin = wrap(leftE, p, isRight, sym) + ' ' + sym + ' ' + wrap(rightE, p, !isRight, sym);
            }
            this.setExpr(A, ex(codeBin, p), pc);
            pc += (MM_AFTER[op] && code[pc + 1] && /^MMBIN/.test(OPCODES[code[pc + 1].op])) ? 2 : 1;
            continue;
          }
          case 'SHRI': {
            var l1 = this.readRegExpr(B, pc);
            this.setExpr(A, ex(wrap(l1, PREC['>>'], false, '>>') + ' >> ' + fmt(ins.sC), PREC['>>']), pc);
            pc += (code[pc + 1] && /^MMBIN/.test(OPCODES[code[pc + 1].op])) ? 2 : 1;
            continue;
          }
          case 'SHLI': {
            var l2 = this.readRegExpr(B, pc);
            this.setExpr(A, ex(fmt(ins.sC) + ' << ' + wrap(l2, PREC['<<'], true, '<<'), PREC['<<']), pc);
            pc += (code[pc + 1] && /^MMBIN/.test(OPCODES[code[pc + 1].op])) ? 2 : 1;
            continue;
          }
          case 'MMBIN': case 'MMBINI': case 'MMBINK':
            pc++; continue;

          case 'UNM': {
            var u1 = this.readRegExpr(B, pc);
            this.setExpr(A, ex('-' + wrap(u1, PREC.unary, true, ''), PREC.unary), pc);
            pc += (code[pc + 1] && /^MMBIN/.test(OPCODES[code[pc + 1].op])) ? 2 : 1;
            continue;
          }
          case 'BNOT': {
            var u2 = this.readRegExpr(B, pc);
            this.setExpr(A, ex('~' + wrap(u2, PREC.unary, true, ''), PREC.unary), pc);
            pc += (code[pc + 1] && /^MMBIN/.test(OPCODES[code[pc + 1].op])) ? 2 : 1;
            continue;
          }
          case 'NOT': {
            var u3 = this.readRegExpr(B, pc);
            this.setExpr(A, ex(negate(u3.code), PREC.unary), pc);
            pc++; continue;
          }
          case 'LEN': {
            var u4 = this.readRegExpr(B, pc);
            this.setExpr(A, ex('#' + wrap(u4, PREC.unary, true, ''), PREC.unary), pc);
            pc++; continue;
          }
          case 'CONCAT': {
            var partsTxt = [];
            for (var ci = 0; ci < B; ci++) partsTxt.push(this.readRegExpr(A + ci, pc));
            var joined = '';
            for (var cj = 0; cj < partsTxt.length; cj++) {
              joined += wrap(partsTxt[cj], PREC['..'], cj === partsTxt.length - 1, '..');
              if (cj !== partsTxt.length - 1) joined += ' .. ';
            }
            this.setExpr(A, ex(joined, PREC['..']), pc);
            pc++; continue;
          }

          case 'CLOSURE': {
            var sub = this.proto.protos[ins.Bx];
            if (!sub) { this.emit('-- [!] prototype ' + ins.Bx + ' introuvable'); pc++; continue; }
            this.setExpr(A, ex(this.buildFunction(sub), ATOM), pc);
            pc += 1 + sub.upvalues.length;
            continue;
          }

          case 'CALL': {
            var selfInfo = this.selfCalls[A];
            var callTxt;
            var argsTxt = [];
            var argLimit = B === 0 ? this.proto.maxstacksize : B;
            var firstArg = selfInfo ? 2 : 1;
            for (var ai = firstArg; ai < argLimit; ai++) {
              if (B === 0 && !this.regs[A + ai] && !this.localName(A + ai, pc)) break;
              argsTxt.push(this.readRegExpr(A + ai, pc).code);
            }
            if (B === 0) {
              argsTxt.push(this.openTail || '...');
              this.openTail = null;
            }
            if (selfInfo) {
              if (selfInfo.ident) {
                callTxt = selfInfo.recv + ':' + selfInfo.ident + '(' + argsTxt.join(', ') + ')';
              } else {
                callTxt = selfInfo.recv + '[' + selfInfo.name + '](' + selfInfo.recv +
                  (argsTxt.length ? ', ' + argsTxt.join(', ') : '') + ')';
              }
            } else {
              callTxt = this.readRegExpr(A, pc).code + '(' + argsTxt.join(', ') + ')';
            }
            var nres = C === 0 ? -1 : C - 1;
            if (nres < 0) {
              this.openTail = callTxt;
            } else if (nres === 0) {
              this.emit(callTxt);
            } else if (nres === 1) {
              if (this.usesBeforeClobber(A, pc) === 0) {
                this.emit(callTxt);
              } else {
                this.setExpr(A, ex(callTxt, ATOM, { callSeq: this.stmtSeq }), pc);
                this.lastCallInfo = { fromA: A, results: 1, text: callTxt, lineIndex: this.lines.length - 1 };
              }
            } else {
              var count = nres < 0 ? 3 : nres;
              var namesL = [];
              for (var ni = 0; ni < count; ni++) {
                namesL.push(this.localName(A + ni, pc) || this.declName(A + ni, pc) || this.temp());
              }
              this.emit('local ' + namesL.join(', ') + ' = ' + callTxt);
              for (var nr = 0; nr < count; nr++) {
                this.regs[A + nr] = ex(namesL[nr], ATOM);
                this.declared[A + nr] = true;
              }
              this.lastCallInfo = { fromA: A, results: count, text: callTxt, lineIndex: this.lines.length - 1 };
            }
            delete this.selfCalls[A];
            for (var rz = A; rz < A + (nres < 0 ? 3 : nres); rz++) this.regs[rz] = this.regs[rz] || null;
            pc++; continue;
          }

          case 'TAILCALL': {
            var selfT = this.selfCalls[A];
            var argsT = [];
            var limT = B === 0 ? this.proto.maxstacksize : B;
            for (var ti = selfT ? 2 : 1; ti < limT; ti++) {
              if (B === 0 && !this.regs[A + ti] && !this.localName(A + ti, pc)) break;
              argsT.push(this.readRegExpr(A + ti, pc).code);
            }
            if (B === 0) {
              argsT.push(this.openTail || '...');
              this.openTail = null;
            }
            var tailTxt = selfT
              ? selfT.recv + ':' + selfT.name + '(' + argsT.join(', ') + ')'
              : this.readRegExpr(A, pc).code + '(' + argsT.join(', ') + ')';
            this.emit('return ' + tailTxt);
            pc = end; continue;
          }

          case 'RETURN': {
            var vals = [];
            if (B === 0) {
              for (var ri = A; ri < this.proto.maxstacksize; ri++) {
                if (!this.regs[ri] && !this.localName(ri, pc)) break;
                vals.push(this.readRegExpr(ri, pc).code);
              }
            } else {
              for (var rj = 0; rj < B - 1; rj++) vals.push(this.readRegExpr(A + rj, pc).code);
            }
            this.flushAllTables(pc);
            this.emit(vals.length ? 'return ' + vals.join(', ') : 'return');
            pc = end; continue;
          }
          case 'RETURN0': this.flushAllTables(pc); this.emit('return'); pc = end; continue;
          case 'RETURN1': this.flushAllTables(pc); this.emit('return ' + this.readRegExpr(A, pc).code); pc = end; continue;

          case 'FORPREP': {
            var loopPc = pc + 1 + ins.Bx;
            var initE = this.readRegExpr(A, pc).code;
            var limitE = this.readRegExpr(A + 1, pc).code;
            var stepE = this.readRegExpr(A + 2, pc).code;
            var varName = this.nameNear(A + 3, pc + 1) || ('v' + (A + 4));
            var head = 'for ' + varName + ' = ' + initE + ', ' + limitE;
            if (stepE !== '1' && stepE !== 'nil') head += ', ' + stepE;
            this.emit(head + ' do');
            this.indent++;
            this.regs[A] = null; this.regs[A + 1] = null; this.regs[A + 2] = null;
            this.regs[A + 3] = ex(varName, ATOM);
            this.withScope(function (self) { self.emitRange(pc + 1, Math.min(loopPc, end), depth + 1); });
            this.indent--;
            this.emit('end');
            pc = loopPc + 1;
            continue;
          }

          case 'TFORPREP': {
            var callPc = pc + 1 + ins.Bx;
            var fE = this.readRegExpr(A, pc).code;
            var sE = this.readRegExpr(A + 1, pc).code;
            var cE = this.readRegExpr(A + 2, pc).code;
            var iterTxt;
            if (this.lastCallInfo && this.lastCallInfo.fromA === A && this.lastCallInfo.lineIndex === this.lines.length - 1) {
              this.lines.pop();
              iterTxt = this.lastCallInfo.text;
              this.lastCallInfo = null;
            } else if (cE && cE !== 'nil') {
              iterTxt = fE + ', ' + sE + ', ' + cE;
            } else {
              iterTxt = fE + '(' + sE + ')';
            }
            var varsL = [];
            for (var vi = 0; vi < 4; vi++) {
              var nm = this.nameNear(A + 4 + vi, pc + 1);
              if (nm) varsL.push(nm);
              else if (vi === 0) { varsL.push('k'); }
              else if (vi === 1) { varsL.push('v'); }
              else break;
            }
            this.emit('for ' + varsL.join(', ') + ' in ' + iterTxt + ' do');
            this.indent++;
            for (var q = 0; q < varsL.length; q++) this.regs[A + 4 + q] = ex(varsL[q], ATOM);
            this.withScope(function (self) { self.emitRange(pc + 1, Math.min(callPc, end), depth + 1); });
            this.indent--;
            this.emit('end');
            pc = callPc + 2;
            continue;
          }

          case 'FORLOOP': case 'TFORLOOP': case 'TFORCALL':
            pc++; continue;

          case 'SETLIST': {
            var tbl = this.tables[A];
            var cnt = B;
            var base = (C - 1) * 50;
            if (B === 0) {
              cnt = 0;
              for (var si = A + 1; si < this.proto.maxstacksize; si++) {
                if (!this.regs[si] && !this.localName(si, pc)) break;
                cnt++;
              }
            }
            if (ins.k && code[pc + 1] && OPCODES[code[pc + 1].op] === 'EXTRAARG') {
              base = (code[pc + 1].Ax - 1) * 50;
              pc++;
            }
            if (tbl) {
              if (this.openTail) {
                tbl.items.push(this.openTail);
                this.openTail = null;
              } else {
                for (var sj = 1; sj <= cnt; sj++) tbl.items.push(this.readRegExpr(A + sj, pc).code);
              }
            }
            pc++; continue;
          }

          case 'VARARG': {
            if (C === 0) { this.openTail = '...'; pc++; continue; }
            this.setExpr(A, ex('...', ATOM), pc);
            pc++; continue;
          }

          case 'JMP': {
            var jt = pc + 1 + ins.sJ;
            if (jt >= end) { this.emit('break'); pc = end; continue; }
            this.emitGoto(jt, 'saut pc ' + pc);
            pc++;
            continue;
          }

          case 'TEST': case 'TESTSET': {
            this.lastCond = this.testCondition(pc);
            pc++; continue;
          }

          default:
            this.emit('-- [instruction non prise en charge : ' + op + ' pc ' + pc + ']');
            pc++; continue;
        }
      }
    };

    /* Exécute un bloc imbriqué en isolant la portée des déclarations */
    FnEmitter.prototype.withScope = function (fn) {
      var saved = {};
      for (var k in this.declared) saved[k] = this.declared[k];
      fn(this);
      for (var r in this.declared) if (!(r in saved)) delete this.declared[r];
      for (var q in saved) this.declared[q] = saved[q];
    };

    FnEmitter.prototype.buildFunction = function (sub) {
      var child = new FnEmitter(sub, {
        warnings: this.warnings,
        tempCounter: this.tempCounter,
        isNested: true
      });
      var sig = child.signature();
      var head = 'function(' + sig.params.join(', ') + ')';
      child.emitRange(0, sub.code.length);
      child.flushAllTables();
      var body = child.lines.filter(function (l) { return l.trim().length; });
      if (!body.length) return head + '\nend';
      return head + '\n' + body.map(function (l) { return '  ' + l; }).join('\n') + '\nend';
    };

    FnEmitter.prototype.signature = function () {
      var p = this.proto;
      var params = [];
      for (var i = 0; i < p.numparams; i++) params.push(this.localName(i, 0) || ('p' + (i + 1)));
      if (p.is_vararg) params.push('...');
      return { params: params };
    };

    /* ------------------------------------------------------------------ *
     * Point d'entrée
     * ------------------------------------------------------------------ */
    function decompile(mainProto, options) {
      options = options || {};
      var warnings = [];
      var em = new FnEmitter(mainProto, { warnings: warnings, tempCounter: { n: 0 } });
      em.emitRange(0, mainProto.code.length);
      em.flushAllTables();
      var body = em.lines;

      var header = [];
      header.push('-- Reconstruction depuis bytecode Lua 5.4');
      if (options.fileName) header.push('-- fichier : ' + options.fileName);
      header.push('-- chunk principal : ' + (mainProto.source || '?') +
        ' (lignes ' + mainProto.linedefined + '-' + mainProto.lastlinedefined + ')');
      if (!mainProto.debug.lineinfo.length) {
        header.push('-- note : chunk strippé (aucune information de debug) — noms de variables générés');
      }
      header.push('-- reconstruction heuristique : à relire avant toute réutilisation');
      header.push('');

      var text = body.filter(function (l) { return l.trim().length; }).join('\n');
      var out = header.join('\n') + '\n' + text + '\n';

      if (em.usedGoto) {
        warnings.push('Certaines structures n\'ont pas pu être reconstruites : elles apparaissent en goto/étiquettes.');
      }
      return { code: out, warnings: warnings };
    }

    L.decompile = decompile;
    L.countRegReads = countRegReads;
  }

  if (typeof module === 'object' && module.exports) {
    install(require('./lua54.js'));
    module.exports = require('./lua54.js');
  } else {
    install(root.Lua54);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
