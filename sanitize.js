/* sanitize.js — nettoyage défensif tout-langage : neutralise les motifs dangereux
   connus, puis applique le nettoyage/formatage du langage détecté.
   Les lignes retirées sont commentées, jamais supprimées : rien n'est perdu. */
(function (root) {
  'use strict';

  var MARK = 'AntiCleanBackdoor';

  var LUA_TARGETS = [
    { id: 'os_execute', title: 'os.execute', re: /os\s*\.\s*execute\s*\(/ },
    { id: 'io_popen', title: 'io.popen', re: /io\s*\.\s*popen\s*\(/ },
    { id: 'io_write', title: 'io.open en écriture', re: /io\s*\.\s*open\s*\([^)]*["'][wa]/ },
    { id: 'load', title: 'chargement dynamique', re: /\b(?:load|loadstring)\s*\(/ },
    { id: 'debug_hook', title: 'hook debug', re: /debug\s*\.\s*(?:sethook|setupvalue|getinfo)\s*\(/ },
    { id: 'setfenv', title: 'setfenv/getfenv', re: /\b(?:setfenv|getfenv)\b/ },
    { id: 'env_write', title: 'écriture dans _G', re: /(?:setmetatable\s*\(\s*_G|rawset\s*\(\s*_G)/ },
    { id: 'exec_cmd', title: 'ExecuteCommand', re: /ExecuteCommand\s*\(/ },
    { id: 'http_ip', title: 'HTTP vers une IP brute', re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ },
    { id: 'save_file', title: 'SaveResourceFile', re: /SaveResourceFile\s*\(/ }
  ];

  var JS_TARGETS = [
    { id: 'eval', title: 'eval', re: /\beval\s*\(/ },
    { id: 'new_function', title: 'new Function', re: /new\s+Function\s*\(/ },
    { id: 'cookie', title: 'document.cookie', re: /document\s*\.\s*cookie/ },
    { id: 'fetch_remote', title: 'fetch distant', re: /\bfetch\s*\(\s*["'`]https?:\/\// },
    { id: 'ws_remote', title: 'WebSocket distant', re: /new\s+WebSocket\s*\(\s*["'`]wss?:\/\// },
    { id: 'xhr', title: 'XMLHttpRequest', re: /XMLHttpRequest/ },
    { id: 'postmessage_star', title: 'postMessage « * »', re: /postMessage\s*\([^)]*,\s*["'`]\*["'`]/ }
  ];

  function kindOf(name, text) {
    var k = root.Nui && root.Nui.kindOf ? root.Nui.kindOf(name) : null;
    if (k) return k;
    if (/\.lua$/i.test(String(name))) return 'lua';
    var head = String(text || '').slice(0, 800);
    var low = head.toLowerCase();
    if (/<!doctype html|<html|<body|<div|<script/.test(low)) return 'html';
    if (/^\s*(?:\/\*[\s\S]*?\*\/\s*)?[.#@][\w-]+\s*\{/m.test(head) && !/\bfunction\b/.test(head)) return 'css';
    if (/\bfunction\b|\b(?:var|let|const)\s|=>|require\s*\(/.test(head)) return 'js';
    if (/^\s*(?:local|function)\s|\bend\b\s*$/m.test(head)) return 'lua';
    return 'text';
  }

  function balanced(line) {
    var opens = (line.match(/[({[]/g) || []).length;
    var closes = (line.match(/[)}\]]/g) || []).length;
    return opens === closes;
  }

  function neutralize(line, comment, title) {
    var trimmed = line.trim();
    if (!trimmed) return line;
    var indent = /^[ \t]*/.exec(line)[0];
    return indent + comment + ' [retiré: ' + title + '] ' + trimmed;
  }

  function scanOf(text, kind) {
    if (kind === 'lua') return root.Anti.scanLua(text, 'source');
    if (kind === 'text') return { counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [] };
    return root.Nui.scan(text, kind, 'fichier');
  }

  function stripComments(text, kind) {
    if (kind === 'lua' && root.Anti && root.Anti.codeOnly) return root.Anti.codeOnly(text);
    if (kind === 'js') return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    if (kind === 'css') return text.replace(/\/\*[\s\S]*?\*\//g, '');
    if (kind === 'html') return text.replace(/<!--[\s\S]*?-->/g, '');
    return text;
  }

  function stripLua(src, removed) {
    var lines = src.split('\n');
    var manual = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*--/.test(line)) continue;
      var hit = null;
      for (var r = 0; r < LUA_TARGETS.length; r++) {
        if (LUA_TARGETS[r].re.test(line)) { hit = LUA_TARGETS[r]; break; }
      }
      if (!hit) continue;
      if (!balanced(line)) {
        manual.push({ line: i + 1, title: hit.title, snippet: line.trim() });
        continue;
      }
      lines[i] = neutralize(line, '--', hit.title);
      removed.push({ line: i + 1, title: hit.title, snippet: line.trim() });
    }
    return { code: lines.join('\n'), manual: manual };
  }

  function stripJs(src, removed) {
    var lines = src.split('\n');
    var manual = [];
    var inBlock = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (inBlock) {
        if (line.indexOf('*/') !== -1) inBlock = false;
        continue;
      }
      if (/^\s*\/\//.test(line)) continue;
      var hit = null;
      for (var r = 0; r < JS_TARGETS.length; r++) {
        if (JS_TARGETS[r].re.test(line)) { hit = JS_TARGETS[r]; break; }
      }
      if (!hit) continue;
      if (!balanced(line)) {
        manual.push({ line: i + 1, title: hit.title, snippet: line.trim() });
        continue;
      }
      lines[i] = neutralize(line, '//', hit.title);
      removed.push({ line: i + 1, title: hit.title, snippet: line.trim() });
    }
    return { code: lines.join('\n'), manual: manual };
  }

  function stripHtml(src, removed) {
    var out = src;
    var count = 0;

    out = out.replace(/<script\b[^>]*src\s*=\s*["']https?:\/\/[^>]*>[\s\S]*?<\/script>/gi, function (m) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'script distant', snippet: m.slice(0, 120) });
      return '<!-- [' + MARK + ': script distant retiré] -->';
    });

    out = out.replace(/<script\b[^>]*src\s*=\s*["']data:text\/javascript[^>]*>[\s\S]*?<\/script>/gi, function (m) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'script data: URI', snippet: m.slice(0, 120) });
      return '<!-- [' + MARK + ': script data: retiré] -->';
    });

    out = out.replace(/<iframe\b[^>]*src\s*=\s*["']https?:\/\/[^>]*>[\s\S]*?<\/iframe>/gi, function (m) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'iframe distante', snippet: m.slice(0, 120) });
      return '<!-- [' + MARK + ': iframe distante retirée] -->';
    });

    out = out.replace(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*>/gi, function (m) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'meta refresh', snippet: m.slice(0, 120) });
      return '<!-- [' + MARK + ': meta refresh retiré] -->';
    });

    out = out.replace(/\son(?:error|load|click|mouseover|mouseenter|focus)\s*=\s*("[^"]*"|'[^']*')/gi, function (m) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'gestionnaire inline', snippet: m.slice(0, 120) });
      return '';
    });

    out = out.replace(/\b(href|src)\s*=\s*["']javascript:[^"']*["']/gi, function (m, attr) {
      count++;
      removed.push({ line: lineAt(src, m), title: 'URL javascript:', snippet: m.slice(0, 120) });
      return attr + '="#"';
    });

    return { code: out, manual: [], removedCount: count };
  }

  function stripCss(src, removed) {
    var out = src;

    out = out.replace(/@import\b[^;]*https?:\/\/[^;]*;/gi, function (m) {
      removed.push({ line: lineAt(src, m), title: '@import distant', snippet: m.slice(0, 120) });
      return '/* [' + MARK + ': @import distant retiré] */';
    });

    out = out.replace(/[^;{}]*url\(\s*["']?https?:\/\/[^;{}]*;/gi, function (m) {
      removed.push({ line: lineAt(src, m), title: 'ressource distante', snippet: m.slice(0, 120) });
      return '/* [' + MARK + ': url distante retirée] */';
    });

    out = out.replace(/expression\s*\([^)]*\)/gi, function (m) {
      removed.push({ line: lineAt(src, m), title: 'expression()', snippet: m.slice(0, 120) });
      return 'none';
    });

    out = out.replace(/behavior\s*:[^;]*;/gi, function (m) {
      removed.push({ line: lineAt(src, m), title: 'behavior', snippet: m.slice(0, 120) });
      return '/* [' + MARK + ': behavior retiré] */';
    });

    return { code: out, manual: [] };
  }

  function lineAt(src, needle) {
    var idx = src.indexOf(needle);
    if (idx < 0) return 0;
    var n = 1;
    for (var i = 0; i < idx; i++) if (src.charCodeAt(i) === 10) n++;
    return n;
  }

  function run(text, name) {
    var src = String(text || '');
    var kind = kindOf(name, src);
    var removed = [];
    var manual = [];
    var warnings = [];
    var hadBom = /^\uFEFF/.test(src);
    var crlf = /\r\n/.test(src);

    var before = scanOf(src, kind);

    var stripped;
    if (kind === 'lua') stripped = stripLua(src, removed);
    else if (kind === 'js') stripped = stripJs(src, removed);
    else if (kind === 'html') stripped = stripHtml(src, removed);
    else if (kind === 'css') stripped = stripCss(src, removed);
    else stripped = { code: src, manual: [] };

    manual = stripped.manual || [];
    var body = stripped.code;

    var cleaned;
    if (kind === 'lua' && root.Anti) {
      cleaned = root.Anti.cleanLua(body);
    } else if (root.Nui && (kind === 'html' || kind === 'css' || kind === 'js')) {
      cleaned = root.Nui.clean(body, kind);
    } else {
      var generic = body.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n')
        .split('\n').map(function (l) { return l.replace(/[ \t]+$/, ''); }).join('\n')
        .replace(/\n{3,}/g, '\n\n');
      cleaned = { code: generic, log: [{ pass: 'mise en forme', detail: 'BOM, fins de ligne et espaces normalisés' }], warnings: [] };
    }

    var code = cleaned.code;
    if (!code.endsWith('\n')) code += '\n';

    var afterScan = scanOf(stripComments(code, kind), kind);

    if (hadBom) warnings.push('BOM UTF-8 retiré.');
    if (crlf) warnings.push('Fins de ligne CRLF converties en LF.');
    if (manual.length) {
      warnings.push(manual.length + ' motif(s) sur plusieurs lignes laissé(s) tel quel(s) : à retirer à la main (voir la liste).');
    }
    if (afterScan.counts.critical > 0) {
      warnings.push(afterScan.counts.critical + ' constat(s) critique(s) subsiste(nt) après nettoyage : le code restant mérite une relecture.');
    }

    return {
      code: code,
      kind: kind,
      removed: removed,
      manual: manual,
      warnings: (cleaned.warnings || []).concat(warnings),
      log: cleaned.log || [],
      before: before.counts,
      after: afterScan.counts,
      stats: {
        beforeBytes: src.length,
        afterBytes: code.length,
        removedCount: removed.length,
        manualCount: manual.length
      }
    };
  }

  root.Sanitize = {
    kindOf: kindOf,
    run: run
  };
})(typeof window !== 'undefined' ? window : globalThis);
