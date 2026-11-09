/* anti.js — audit statique et nettoyage de code Lua (contexte FiveM).
   Aucune exécution du code analysé : uniquement des motifs et des heuristiques. */
(function (root) {
  'use strict';

  var SEVERITY = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  var LUA_RULES = [
    { id: 'os_execute', severity: 'critical', title: 'Exécution de commande système',
      re: /os\s*\.\s*execute\s*\(/g,
      why: 'Lance une commande arbitraire sur la machine qui exécute la ressource.',
      advice: 'Supprimez l’appel. Une ressource légitime n’a aucune raison d’appeler os.execute.' },

    { id: 'io_popen', severity: 'critical', title: 'Tube de commande système',
      re: /io\s*\.\s*popen\s*\(/g,
      why: 'Ouvre un processus et lit sa sortie : exécution arbitraire, souvent utilisée pour du shell.',
      advice: 'Supprimez l’appel ou isolez le fichier : il n’a rien à faire dans une ressource de jeu.' },

    { id: 'io_write', severity: 'high', title: 'Écriture de fichier',
      re: /io\s*\.\s*open\s*\([^)]*["'][wa]/g,
      why: 'Écrit sur le disque (persistance, dépôt de charge utile, altération de fichiers).',
      advice: 'Vérifiez le chemin visé ; préférez les KVP FiveM pour de la persistance légitime.' },

    { id: 'http_out', severity: 'high', title: 'Requête HTTP sortante',
      re: /PerformHttpRequest\s*\(/g,
      why: 'Contacte un serveur distant : télémétrie, licence, mais aussi exfiltration de données.',
      advice: 'Lisez l’URL et la charge envoyée. Toute donnée joueur transmise doit être justifiée.' },

    { id: 'http_ip', severity: 'critical', title: 'URL vers une adresse IP brute',
      re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
      why: 'Un serveur distant désigné par IP évite tout nom de domaine traçable (C2, panel de revente).',
      advice: 'Traitez comme hostile tant que l’auteur ne justifie pas l’adresse.' },

    { id: 'http_url', severity: 'medium', title: 'URL codée en dur',
      re: /https?:\/\/[A-Za-z0-9._~:\/?#\[\]@!$&'()*+,;=%-]{4,}/g,
      why: 'Point de sortie réseau à auditer : identifiez qui reçoit quoi.',
      advice: 'Documentez l’endpoint ou supprimez-le.' },

    { id: 'load_dynamic', severity: 'critical', title: 'Chargement dynamique de code',
      re: /\b(?:load|loadstring|assert\s*\(\s*load|pcall\s*\(\s*load)\s*\(/g,
      why: 'Exécute du code construit à l’exécution : vecteur classique de backdoor obfusquée.',
      advice: 'Désobfusquez la source dans l’onglet « Source obfusquée » avant d’accepter le fichier.' },

    { id: 'load_char', severity: 'critical', title: 'load(string.char(...))',
      re: /load\s*\(\s*string\s*\.\s*char\s*\(/g,
      why: 'Charge un programme reconstruit octet par octet : signature typique d’un dropper.',
      advice: 'Extrayez les octets et lisez le code obtenu. Ne chargez pas la ressource en l’état.' },

    { id: 'string_dump', severity: 'medium', title: 'string.dump',
      re: /string\s*\.\s*dump\s*\(/g,
      why: 'Recompile du bytecode en mémoire : masque le code réellement exécuté.',
      advice: 'Vérifiez ce qui est dumpé puis rechargé.' },

    { id: 'setfenv', severity: 'high', title: 'Manipulation d’environnement',
      re: /\b(?:setfenv|getfenv|setmetatable\s*\(\s*_G|rawset\s*\(\s*_G)\b/g,
      why: 'Détourne l’environnement global : accès ou surcharge de fonctions du runtime.',
      advice: 'Auditez les touches ajoutées à _G ; elles peuvent intercepter vos propres appels.' },

    { id: 'debug_hook', severity: 'high', title: 'Hook du débogueur',
      re: /debug\s*\.\s*(?:sethook|getinfo|getlocal|setupvalue)\s*\(/g,
      why: 'Observe ou modifie l’exécution d’autres scripts : lecture de variables sensibles.',
      advice: 'Supprimez, sauf outil de développement assumé et documenté.' },

    { id: 'hex_blob', severity: 'high', title: 'Chaîne d’échappements hexadécimaux',
      re: /(?:\\x[0-9a-fA-F]{2}){12,}/g,
      why: 'Texte encodé octet par octet, illisible à l’œil : couche d’obfuscation.',
      advice: 'Désobfusquez avant lecture ; l’onglet « Source obfusquée » reconstruit ces chaînes.' },

    { id: 'char_chain', severity: 'high', title: 'Suite de string.char',
      re: /string\s*\.\s*char\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+/g,
      why: 'Construction de texte à partir de codes numériques : masquage de commandes ou d’URL.',
      advice: 'Désobfusquez, puis relisez la chaîne reconstruite.' },

    { id: 'kvp', severity: 'low', title: 'Stockage KVP',
      re: /(?:Set|Get)ResourceKvp(?:String|Float|Int)?\s*\(/g,
      why: 'Persistance côté client : peut conserver un identifiant ou une configuration cachée.',
      advice: 'Vérifiez la clé écrite et sa valeur.' },

    { id: 'nui', severity: 'low', title: 'Message NUI',
      re: /SendNUIMessage\s*\(/g,
      why: 'Communication avec l’interface : si le JS appelé fait un eval, la chaîne devient exécutable.',
      advice: 'Auditez en parallèle le fichier NUI avec l’onglet « AntiCleanNUI & LUA ».' },

    { id: 'save_file', severity: 'medium', title: 'Écriture de fichier ressource',
      re: /SaveResourceFile\s*\(/g,
      why: 'Modifie les fichiers de la ressource au runtime : auto-modification possible.',
      advice: 'Vérifiez le chemin et le contenu écrit.' },

    { id: 'cmd_execute', severity: 'high', title: 'Exécution de commande console',
      re: /ExecuteCommand\s*\(/g,
      why: 'Lance une commande serveur arbitraire (kick, ban, spawn, restart…).',
      advice: 'Vérifiez que la commande dépend d’une permission et non d’une entrée joueur.' },

    { id: 'remote_untrusted', severity: 'medium', title: 'Événement réseau avec donnée brute',
      re: /RegisterNetEvent\s*\(\s*["'][^"']+["']\s*\)[\s\S]{0,200}?TriggerServerEvent\s*\(\s*["'][^"']+["']\s*,\s*source/g,
      why: 'Relaye une valeur non validée vers le serveur : injection de paramètres.',
      advice: 'Validez types et bornes côté serveur avant tout usage.' }
  ];

  var ARTIFACT_RE = /\b(?:L|l)_(\d+)_?\b/g;

  var LONG_LITERAL_RE = /(["'])([^"'\\\n]{80,})\1/g;

  /* ------------------------------ utilitaires ------------------------------ */

  function shannon(str) {
    var counts = Object.create(null);
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      counts[c] = (counts[c] || 0) + 1;
    }
    var ent = 0;
    for (var k in counts) {
      var p = counts[k] / str.length;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  function lineOf(text, index) {
    var n = 1;
    for (var i = 0; i < index && i < text.length; i++) {
      if (text.charCodeAt(i) === 10) n++;
    }
    return n;
  }

  function snippetAt(text, index) {
    var start = text.lastIndexOf('\n', index - 1) + 1;
    var end = text.indexOf('\n', index);
    if (end === -1) end = text.length;
    var line = text.slice(start, end).trim();
    return line.length > 168 ? line.slice(0, 165) + '…' : line;
  }

  function countMatches(text, re) {
    var n = 0;
    re.lastIndex = 0;
    while (re.exec(text)) {
      n++;
      if (n > 5000) break;
    }
    re.lastIndex = 0;
    return n;
  }

  /* Découpe le source en segments : code, chaîne, commentaire (pour ne pas
     renommer ni réindenter à l'intérieur d'un littéral). */
  function segments(src) {
    var out = [];
    var i = 0;
    var buf = '';
    var n = src.length;

    function flush() {
      if (buf) { out.push({ code: true, text: buf }); buf = ''; }
    }

    while (i < n) {
      var c = src[i];

      /* commentaire long --[[ ... ]] ou --[==[ ... ]==] */
      if (c === '-' && src[i + 1] === '-') {
        var longOpen = /^--\[(=*)\[/.exec(src.slice(i, i + 64));
        if (longOpen) {
          flush();
          var close = ']' + longOpen[1] + ']';
          var endIdx = src.indexOf(close, i + longOpen[0].length);
          if (endIdx === -1) endIdx = n - close.length;
          var piece = src.slice(i, endIdx + close.length);
          out.push({ code: false, text: piece });
          i = endIdx + close.length;
          continue;
        }
        flush();
        var eol = src.indexOf('\n', i);
        if (eol === -1) eol = n;
        out.push({ code: false, text: src.slice(i, eol) });
        i = eol;
        continue;
      }

      /* chaîne longue [[ ... ]] */
      var lng = /^\[(=*)\[/.exec(src.slice(i, i + 32));
      if (lng) {
        flush();
        var closeL = ']' + lng[1] + ']';
        var endL = src.indexOf(closeL, i + lng[0].length);
        if (endL === -1) endL = n - closeL.length;
        out.push({ code: false, text: src.slice(i, endL + closeL.length) });
        i = endL + closeL.length;
        continue;
      }

      if (c === '"' || c === "'") {
        flush();
        var j = i + 1;
        while (j < n) {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === c) { j++; break; }
          if (src[j] === '\n') break;
          j++;
        }
        out.push({ code: false, text: src.slice(i, j) });
        i = j;
        continue;
      }

      buf += c;
      i++;
    }
    flush();
    return out;
  }

  function join(pieces) {
    return pieces.map(function (p) { return p.text; }).join('');
  }

  /* --------------------------------- audit --------------------------------- */

  function scanLua(text, name) {
    var src = String(text || '');
    var findings = [];
    var seen = Object.create(null);

    LUA_RULES.forEach(function (rule) {
      var re = new RegExp(rule.re.source, rule.re.flags.indexOf('g') === -1 ? rule.re.flags + 'g' : rule.re.flags);
      var m;
      var hits = 0;
      while ((m = re.exec(src)) && hits < 25) {
        var line = lineOf(src, m.index);
        var key = rule.id + ':' + line;
        if (!seen[key]) {
          seen[key] = true;
          findings.push({
            id: rule.id,
            severity: rule.severity,
            title: rule.title,
            line: line,
            snippet: snippetAt(src, m.index),
            why: rule.why,
            advice: rule.advice
          });
        }
        hits++;
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    });

    /* boucle infinie : seulement si aucun Wait ni break ne vient la rendre inoffensive */
    var wtRe = /while\s+true\s+do/g;
    var wt;
    while ((wt = wtRe.exec(src)) && findings.length < 400) {
      var windowTxt = src.slice(wt.index, wt.index + 320);
      if (/\bWait\s*\(|\bbreak\b/.test(windowTxt)) continue;
      findings.push({
        id: 'while_true',
        severity: 'medium',
        title: 'Boucle while true sans Wait ni break',
        line: lineOf(src, wt.index),
        snippet: snippetAt(src, wt.index),
        why: 'Occupe un thread complet : gel du client ou du serveur selon le contexte.',
        advice: 'Ajoutez un Wait(0) minimum, ou découpez le travail.'
      });
    }

    /* charge utile encodée : longue chaîne à forte entropie */
    var lm;
    LONG_LITERAL_RE.lastIndex = 0;
    var blobs = 0;
    while ((lm = LONG_LITERAL_RE.exec(src)) && blobs < 10) {
      var body = lm[2];
      if (!/^[A-Za-z0-9+/=_\-\s]+$/.test(body)) continue;
      var ent = shannon(body);
      if (ent < 4.1) continue;
      blobs++;
      findings.push({
        id: 'encoded_blob',
        severity: 'high',
        title: 'Longue chaîne encodée (entropie ' + ent.toFixed(2) + ')',
        line: lineOf(src, lm.index),
        snippet: body.length > 120 ? body.slice(0, 117) + '…' : body,
        why: 'Une chaîne base64/hex de cette taille et de cette entropie est presque toujours du code ou une URL masquée.',
        advice: 'Désobfusquez-la et lisez le résultat avant toute exécution.'
      });
    }

    /* combinaisons qui n'ont aucun sens hors exfiltration */
    var hasHttp = /PerformHttpRequest|https?:\/\//.test(src);
    var hasIdent = /GetPlayerIdentifier|GetPlayerName|GetPlayerEndpoint|GetPlayerToken/.test(src);
    if (hasHttp && hasIdent) {
      findings.push({
        id: 'exfil',
        severity: 'critical',
        title: 'Identifiants joueur + sortie réseau dans le même fichier',
        line: lineOf(src, Math.max(0, src.search(/PerformHttpRequest|https?:\/\//))),
        snippet: snippetAt(src, Math.max(0, src.search(/PerformHttpRequest|https?:\/\//))),
        why: 'Le motif exact d’une exfiltration : lecture de l’identité du joueur puis envoi vers un serveur externe.',
        advice: 'Traitez le fichier comme compromis tant que l’envoi n’est pas justifié et limité.'
      });
    }

    if (/FXAP/.test(src)) {
      findings.push({
        id: 'fxap', severity: 'info', title: 'Marqueur FXAP dans le source',
        line: lineOf(src, src.indexOf('FXAP')),
        snippet: snippetAt(src, src.indexOf('FXAP')),
        why: 'Référence à l’escrow FiveM : fichier probablement protégé puis extrait.',
        advice: 'Croisez avec l’onglet « Clean FXAP & Mapping » si le binaire est disponible.'
      });
    }

    var artifacts = (src.match(ARTIFACT_RE) || []).length;
    if (artifacts) {
      var firstArt = src.match(ARTIFACT_RE);
      findings.push({
        id: 'obf_artifact', severity: artifacts > 20 ? 'medium' : 'low',
        title: artifacts + ' identifiant(s) d’obfuscateur (L_xx)',
        line: lineOf(src, Math.max(0, src.search(ARTIFACT_RE))),
        snippet: firstArt ? firstArt[0] : 'L_01',
        why: 'Les noms L_1_, L_01, l_2_ sont produits mécaniquement par les obfuscateurs : le code a été transformé, pas écrit ainsi.',
        advice: 'Utilisez « AntiCleanLUA » pour renommer ces identifiants et relire un code lisible.'
      });
    }

    findings.sort(function (a, b) {
      var d = SEVERITY[a.severity] - SEVERITY[b.severity];
      return d !== 0 ? d : a.line - b.line;
    });

    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) { counts[f.severity]++; });

    return {
      name: name || 'source.lua',
      kind: 'lua',
      lines: src.split('\n').length,
      findings: findings,
      counts: counts,
      artifacts: artifacts,
      verdict: counts.critical ? 'compromis probable'
        : counts.high ? 'à auditer'
          : counts.medium ? 'à vérifier'
            : 'propre'
    };
  }

  /* ------------------------------- nettoyage ------------------------------- */

  function analyzeLine(line, state) {
    /* renvoie une version « code seul » de la ligne, pour l'analyse structurelle */
    var out = '';
    var i = 0;
    var n = line.length;
    while (i < n) {
      if (state.long) {
        var closeL = ']' + state.long + ']';
        var idx = line.indexOf(closeL, i);
        if (idx === -1) return out + ' ';
        i = idx + closeL.length;
        state.long = null;
        continue;
      }
      var c = line[i];
      if (c === '-' && line[i + 1] === '-') {
        var lo = /^--\[(=*)\[/.exec(line.slice(i));
        if (lo) {
          var cl = ']' + lo[1] + ']';
          var e = line.indexOf(cl, i + lo[0].length);
          if (e === -1) { state.long = lo[1]; return out; }
          i = e + cl.length;
          continue;
        }
        return out;
      }
      var lg = /^\[(=*)\[/.exec(line.slice(i));
      if (lg) {
        var cl2 = ']' + lg[1] + ']';
        var e2 = line.indexOf(cl2, i + lg[0].length);
        if (e2 === -1) { state.long = lg[1]; return out + ' '; }
        i = e2 + cl2.length;
        continue;
      }
      if (c === '"' || c === "'") {
        var j = i + 1;
        while (j < n) {
          if (line[j] === '\\') { j += 2; continue; }
          if (line[j] === c) { j++; break; }
          j++;
        }
        out += ' ';
        i = j;
        continue;
      }
      out += c;
      i++;
    }
    return out;
  }

  var OPENERS = { function: 1, then: 1, do: 1, repeat: 1 };

  function reindent(src) {
    var lines = src.split('\n');
    var state = { long: null };
    var depth = 0;
    var out = [];
    var changed = 0;

    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      if (!raw.trim()) { out.push(''); continue; }

      var wasInLong = !!state.long;
      var code = analyzeLine(raw, state);
      if (wasInLong) { out.push(raw); continue; }

      var words = code.match(/[A-Za-z_]\w*/g) || [];
      var first = words[0] || '';
      var pre = 0;
      if (first === 'end' || first === 'until') pre = -1;
      if (first === 'else' || first === 'elseif') pre = -1;

      var lineDepth = depth + pre;
      if (lineDepth < 0) lineDepth = 0;

      var opens = 0;
      var hasFor = false;
      var hasWhile = false;
      for (var w = 0; w < words.length; w++) {
        var t = words[w];
        if (t === 'for') { hasFor = true; opens++; }
        else if (t === 'while') { hasWhile = true; opens++; }
        else if (t === 'function') opens++;
        else if (t === 'then') opens++;
        else if (t === 'repeat') opens++;
        else if (t === 'do') { if (!hasFor && !hasWhile) opens++; }
        else if (t === 'else') opens++;
        else if (t === 'end' && w > 0) opens--;
      }

      var indent = new Array(lineDepth + 1).join('  ');
      var trimmed = raw.replace(/^[ \t]+/, '').replace(/[ \t]+$/, '');
      var next = indent + trimmed;
      if (next !== raw) changed++;
      out.push(next);

      depth = lineDepth + opens;
      if (depth < 0) depth = 0;
    }

    return { code: out.join('\n'), changed: changed };
  }

  function renameArtifacts(src) {
    var pieces = segments(src);
    var used = Object.create(null);
    (src.match(/[A-Za-z_]\w*/g) || []).forEach(function (w) { used[w] = true; });
    var map = Object.create(null);
    var next = 1;
    var renames = 0;

    var mapped = pieces.map(function (piece) {
      if (!piece.code) return piece.text;
      return piece.text.replace(ARTIFACT_RE, function (all) {
        if (!map[all]) {
          var name = 'v' + next++;
          while (used[name]) name = 'v' + next++;
          used[name] = true;
          map[all] = name;
          renames++;
        }
        return map[all];
      });
    });

    return { code: join(mapped.map(function (t) { return { text: t }; })), renames: renames, map: map };
  }

  function cleanLua(text) {
    var log = [];
    var warnings = [];
    var src = String(text || '').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    var before = src.length;

    var ren = renameArtifacts(src);
    src = ren.code;
    if (ren.renames) {
      log.push({ pass: 'identifiants', detail: ren.renames + ' nom(s) d’obfuscateur renommé(s) (' +
        Object.keys(ren.map).slice(0, 4).join(', ') + (Object.keys(ren.map).length > 4 ? '…' : '') + ') → v1, v2, …' });
    }

    var lines = src.split('\n');
    var kept = [];
    var removed = 0;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*;\s*$/.test(line)) { removed++; continue; }
      if (/^\s*do\s+end\s*;?\s*$/.test(line)) { removed++; continue; }
      if (/^\s*(?:local\s+)?([A-Za-z_]\w*)\s*=\s*\1\s*;?\s*$/.test(line)) { removed++; continue; }
      kept.push(line);
    }
    if (removed) log.push({ pass: 'bruit', detail: removed + ' ligne(s) sans effet supprimée(s) (; seul, do end, auto-affectation)' });

    src = kept.join('\n');

    /* concaténation de littéraux adjacents : "a" .. "b" → "ab" */
    var merges = 0;
    src = src.replace(/(["'])([^"'\\\n]*)\1\s*\.\.\s*(["'])([^"'\\\n]*)\3/g, function (all, q1, a, q2, b) {
      merges++;
      return q1 + a + b + q1;
    });
    if (merges) log.push({ pass: 'concaténation', detail: merges + ' concaténation(s) de littéraux fusionnée(s)' });

    /* lignes vides consécutives */
    var blanks = 0;
    src = src.replace(/\n{3,}/g, function () { blanks++; return '\n\n'; });
    if (blanks) log.push({ pass: 'mise en forme', detail: blanks + ' bloc(s) de lignes vides compacté(s)' });

    var re = reindent(src);
    src = re.code;
    if (re.changed) log.push({ pass: 'indentation', detail: re.changed + ' ligne(s) réindentée(s) à 2 espaces par niveau' });

    var trailing = 0;
    src = src.split('\n').map(function (l) {
      var t = l.replace(/[ \t]+$/, '');
      if (t !== l) trailing++;
      return t;
    }).join('\n');
    if (trailing) log.push({ pass: 'espaces', detail: trailing + ' ligne(s) avec espaces de fin nettoyée(s)' });

    if (!src.endsWith('\n')) src += '\n';

    /* garde-fous : on signale, on ne réécrit pas à l'aveugle */
    var opens = (src.match(/\b(function|then|do|repeat)\b/g) || []).length;
    var closes = (src.match(/\b(end|until)\b/g) || []).length;
    if (Math.abs(opens - closes) > 1) {
      warnings.push('Structure déséquilibrée après nettoyage (' + opens + ' ouvertures, ' + closes + ' fermetures) : vérifiez le fichier avant de l’utiliser.');
    }
    if (/\bgoto\b/.test(src)) {
      warnings.push('Le fichier contient des goto : la réindentation peut les rendre moins lisibles, pas incorrects.');
    }

    return {
      code: src,
      log: log,
      warnings: warnings,
      stats: {
        beforeBytes: before,
        afterBytes: src.length,
        renames: ren.renames,
        removedLines: removed,
        merges: merges,
        renamed: ren.renames
      }
    };
  }

  root.Anti = {
    SEVERITY: SEVERITY,
    rules: LUA_RULES,
    scanLua: scanLua,
    cleanLua: cleanLua,
    codeOnly: function (text) {
      return segments(String(text || ''))
        .filter(function (p) { return p.code; })
        .map(function (p) { return p.text; })
        .join('');
    },
    artifactCount: function (text) { return (String(text).match(ARTIFACT_RE) || []).length; }
  };
})(typeof window !== 'undefined' ? window : globalThis);
