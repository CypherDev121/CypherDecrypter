/* nui.js — audit statique et nettoyage des fichiers NUI (HTML, CSS, JS). */
(function (root) {
  'use strict';

  var SEVERITY = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  var JS_RULES = [
    { id: 'eval', severity: 'critical', title: 'eval()',
      re: /\beval\s*\(/g,
      why: 'Exécute une chaîne comme du code : une NUI compromise peut piloter du JS arbitraire.',
      advice: 'Remplacez par un parsing explicite ou supprimez l’appel.' },

    { id: 'new_function', severity: 'high', title: 'new Function()',
      re: /new\s+Function\s*\(/g,
      why: 'Équivalent d’eval, souvent utilisé pour contourner une recherche de « eval ».',
      advice: 'Supprimez ou remplacez par une fonction statique.' },

    { id: 'atob', severity: 'high', title: 'Décodage base64 (atob)',
      re: /\batob\s*\(/g,
      why: 'Sert à masquer une charge utile avant exécution ou envoi.',
      advice: 'Décodez la chaîne et lisez son contenu avant de garder le fichier.' },

    { id: 'from_char_code', severity: 'medium', title: 'String.fromCharCode',
      re: /String\s*\.\s*fromCharCode\s*\(/g,
      why: 'Construction de texte à partir de codes : masquage de commandes ou d’URL.',
      advice: 'Reconstruisez la chaîne et relisez-la.' },

    { id: 'fetch_remote', severity: 'high', title: 'fetch vers un hôte distant',
      re: /\bfetch\s*\(\s*["'`]https?:\/\//g,
      why: 'Sortie réseau depuis l’interface : télémétrie ou exfiltration de données joueur.',
      advice: 'Vérifiez l’URL ; une NUI FiveM n’a normalement aucune raison d’appeler Internet.' },

    { id: 'xhr', severity: 'medium', title: 'XMLHttpRequest',
      re: /XMLHttpRequest/g,
      why: 'Requête réseau manuelle vers un hôte potentiellement externe.',
      advice: 'Vérifiez l’URL ouverte et les données envoyées.' },

    { id: 'ws', severity: 'high', title: 'WebSocket distant',
      re: /new\s+WebSocket\s*\(\s*["'`]wss?:\/\//g,
      why: 'Canal bidirectionnel persistant vers un serveur tiers.',
      advice: 'Supprimez, sauf usage documenté et vérifié.' },

    { id: 'cookie', severity: 'high', title: 'Accès aux cookies',
      re: /document\s*\.\s*cookie/g,
      why: 'Lecture ou écriture de cookies : souvent la première étape d’un vol de session.',
      advice: 'Une interface FiveM n’a pas besoin des cookies de l’hôte.' },

    { id: 'storage', severity: 'low', title: 'Stockage local',
      re: /(?:local|session)Storage\s*\./g,
      why: 'Conserve un état côté client, parfois un identifiant ou un jeton.',
      advice: 'Vérifiez les clés écrites.' },

    { id: 'postmessage', severity: 'medium', title: 'postMessage avec origine « * »',
      re: /postMessage\s*\([^)]*,\s*["'`]\*["'`]/g,
      why: 'Message accepté par n’importe quelle frame : injection possible.',
      advice: 'Ciblez une origine précise et validez event.origin à la réception.' },

    { id: 'debugger', severity: 'low', title: 'Instruction debugger',
      re: /\bdebugger\b/g,
      why: 'Suspend l’exécution quand les outils de développement sont ouverts.',
      advice: 'Retirez-la du code livré.' },

    { id: 'while_true', severity: 'medium', title: 'Boucle while(true)',
      re: /while\s*\(\s*true\s*\)/g,
      why: 'Occupe le thread principal : interface figée si aucun await n’est présent.',
      advice: 'Ajoutez une sortie ou un await.' },

    { id: 'setinterval', severity: 'low', title: 'setInterval à 0 ms',
      re: /setInterval\s*\([^)]*,\s*0\s*\)/g,
      why: 'Boucle au taux maximal : consommation CPU et rafales de messages NUI.',
      advice: 'Passez à un intervalle réaliste (≥ 100 ms) ou à requestAnimationFrame.' },

    { id: 'hex_blob', severity: 'high', title: 'Bloc d’échappements hexadécimaux',
      re: /(?:\\x[0-9a-fA-F]{2}){12,}/g,
      why: 'Texte encodé octet par octet, illisible : obfuscation classique.',
      advice: 'Décodez puis relisez le contenu.' },

    { id: 'long_b64', severity: 'high', title: 'Longue chaîne base64',
      re: /(["'`])[A-Za-z0-9+/=]{160,}\1/g,
      why: 'Charge utile encodée, presque toujours exécutée ou envoyée ensuite.',
      advice: 'Décodez-la avant d’accepter le fichier.' },

    { id: 'innerhtml', severity: 'low', title: 'Écriture via innerHTML',
      re: /\.innerHTML\s*=/g,
      why: 'Injecte du HTML arbitraire : XSS si la valeur vient du jeu.',
      advice: 'Préférez textContent quand la valeur est dynamique.' },

    { id: 'doc_write', severity: 'medium', title: 'document.write',
      re: /document\s*\.\s*write\s*\(/g,
      why: 'Injecte du markup à l’exécution, souvent pour charger un script distant.',
      advice: 'Supprimez.' }
  ];

  var HTML_RULES = [
    { id: 'script_remote', severity: 'high', title: 'Script chargé depuis un hôte distant',
      re: /<script[^>]+src\s*=\s*["']https?:\/\//gi,
      why: 'Le code réellement exécuté vient de l’extérieur : contrôle total de l’auteur distant.',
      advice: 'Hébergez la bibliothèque localement, ou supprimez la balise.' },

    { id: 'script_data', severity: 'critical', title: 'Script en data: URI',
      re: /src\s*=\s*["']data:text\/javascript/gi,
      why: 'Charge du code inline encodé, invisible à la relecture.',
      advice: 'Supprimez immédiatement.' },

    { id: 'inline_handler', severity: 'medium', title: 'Gestionnaire inline (on…)',
      re: /\son(?:error|load|click|mouseover|mouseenter|focus)\s*=\s*["']/gi,
      why: 'Code exécuté à l’événement, souvent ajouté après coup et difficile à tracer.',
      advice: 'Déplacez la logique dans un fichier JS avec addEventListener.' },

    { id: 'iframe', severity: 'medium', title: 'iframe intégrée',
      re: /<iframe\b/gi,
      why: 'Peut afficher une page distante ou masquer du contenu intrusif.',
      advice: 'Vérifiez la source ; supprimez si elle est inutile.' },

    { id: 'meta_refresh', severity: 'high', title: 'Redirection meta refresh',
      re: /<meta[^>]+http-equiv\s*=\s*["']?refresh/gi,
      why: 'Redirige l’interface vers une autre page, parfois après collecte de données.',
      advice: 'Supprimez.' },

    { id: 'js_url', severity: 'high', title: 'Lien javascript:',
      re: /(?:href|src)\s*=\s*["']javascript:/gi,
      why: 'Code exécuté au clic, contourne les vérifications de fichier.',
      advice: 'Remplacez par un gestionnaire d’événement explicite.' },

    { id: 'form_remote', severity: 'medium', title: 'Formulaire vers un hôte distant',
      re: /<form[^>]+action\s*=\s*["']https?:\/\//gi,
      why: 'Envoie les champs saisis vers un serveur tiers.',
      advice: 'Supprimez l’action distante.' }
  ];

  var CSS_RULES = [
    { id: 'import_remote', severity: 'medium', title: '@import distant',
      re: /@import\s+(?:url\()?\s*["']?https?:\/\//gi,
      why: 'Charge une feuille externe : suivi ou injection de styles.',
      advice: 'Emballez les styles localement.' },

    { id: 'url_remote', severity: 'medium', title: 'Ressource distante (url)',
      re: /url\(\s*["']?https?:\/\//gi,
      why: 'Chaque chargement révèle l’activité de l’interface à un tiers (pixel de suivi).',
      advice: 'Hébergez l’image ou la police dans la ressource.' },

    { id: 'expression', severity: 'critical', title: 'CSS expression()',
      re: /expression\s*\(/gi,
      why: 'Exécute du JavaScript depuis une feuille de style (anciens moteurs IE).',
      advice: 'Supprimez : aucun usage légitime.' },

    { id: 'behavior', severity: 'high', title: 'Propriété behavior',
      re: /behavior\s*:/gi,
      why: 'Attache un composant externe au style, vecteur d’exécution historique.',
      advice: 'Supprimez.' }
  ];

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

  function kindOf(name) {
    var n = String(name || '').toLowerCase();
    if (/\.html?$/.test(n)) return 'html';
    if (/\.css$/.test(n)) return 'css';
    if (/\.m?js$/.test(n)) return 'js';
    return null;
  }

  function runRules(src, rules) {
    var findings = [];
    rules.forEach(function (rule) {
      var re = new RegExp(rule.re.source, rule.re.flags);
      var m;
      var hits = 0;
      while ((m = re.exec(src)) && hits < 25) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          line: lineOf(src, m.index),
          snippet: snippetAt(src, m.index),
          why: rule.why,
          advice: rule.advice
        });
        hits++;
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    });
    return findings;
  }

  function scan(text, kind, name) {
    var src = String(text || '');
    var rules = kind === 'html' ? HTML_RULES.concat(JS_RULES) : kind === 'css' ? CSS_RULES : JS_RULES;
    var findings = runRules(src, rules);

    if (kind !== 'css' && /atob\s*\(/.test(src) && /eval\s*\(|new\s+Function\s*\(/.test(src)) {
      findings.push({
        id: 'atob_eval',
        severity: 'critical',
        title: 'base64 décodé puis exécuté',
        line: lineOf(src, src.search(/eval\s*\(|new\s+Function\s*\(/)),
        snippet: snippetAt(src, src.search(/eval\s*\(|new\s+Function\s*\(/)),
        why: 'Le couple atob + eval est la signature d’une charge utile obfusquée.',
        advice: 'Traitez le fichier comme compromis jusqu’au décodage complet.'
      });
    }

    if (kind === 'js' && /SendNUIMessage|fetch\s*\(/.test(src) && /document\s*\.\s*cookie/.test(src)) {
      findings.push({
        id: 'nui_exfil',
        severity: 'critical',
        title: 'Cookies lus + envoi réseau',
        line: lineOf(src, src.search(/document\s*\.\s*cookie/)),
        snippet: snippetAt(src, src.search(/document\s*\.\s*cookie/)),
        why: 'Lecture d’un secret puis transmission : exfiltration caractérisée.',
        advice: 'Supprimez le fichier de la ressource.'
      });
    }

    findings.sort(function (a, b) {
      var d = SEVERITY[a.severity] - SEVERITY[b.severity];
      return d !== 0 ? d : a.line - b.line;
    });

    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) { counts[f.severity]++; });

    return {
      name: name || ('fichier.' + kind),
      kind: kind,
      lines: src.split('\n').length,
      findings: findings,
      counts: counts,
      verdict: counts.critical ? 'compromis probable'
        : counts.high ? 'à auditer'
          : counts.medium ? 'à vérifier'
            : 'propre'
    };
  }

  function clean(text, kind) {
    var log = [];
    var warnings = [];
    var src = String(text || '').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
    var before = src.length;

    if (kind === 'js') {
      var dbg = 0;
      src = src.replace(/^[ \t]*debugger[ \t]*;?[ \t]*\n/gm, function () { dbg++; return ''; });
      if (dbg) log.push({ pass: 'debugger', detail: dbg + ' instruction(s) debugger retirée(s)' });
    }

    if (kind === 'css') {
      var semi = 0;
      src = src.replace(/;;+/g, function () { semi++; return ';'; });
      if (semi) log.push({ pass: 'css', detail: semi + ' point-virgule(s) doublé(s) réduit(s)' });
    }

    var blanks = 0;
    src = src.replace(/\n{3,}/g, function () { blanks++; return '\n\n'; });
    if (blanks) log.push({ pass: 'mise en forme', detail: blanks + ' bloc(s) de lignes vides compacté(s)' });

    var trailing = 0;
    src = src.split('\n').map(function (l) {
      var t = l.replace(/[ \t]+$/, '');
      if (t !== l) trailing++;
      return t;
    }).join('\n');
    if (trailing) log.push({ pass: 'espaces', detail: trailing + ' ligne(s) avec espaces de fin nettoyée(s)' });

    if (!src.endsWith('\n')) src += '\n';

    var opens = (src.match(/<([a-zA-Z][\w-]*)\b(?![^>]*\/>)/g) || []).length;
    if (kind === 'html' && /<html\b/i.test(src)) {
      var closed = (src.match(/<\/[a-zA-Z][\w-]*>/g) || []).length;
      if (closed < opens - 2) {
        warnings.push('Balises possiblement non fermées (' + opens + ' ouvertures, ' + closed + ' fermetures) : vérifiez le rendu.');
      }
    }
    if (kind === 'js') {
      var braces = (src.match(/{/g) || []).length - (src.match(/}/g) || []).length;
      if (braces !== 0) warnings.push('Accolades déséquilibrées (' + braces + ') après nettoyage.');
    }

    return {
      code: src,
      log: log,
      warnings: warnings,
      stats: { beforeBytes: before, afterBytes: src.length }
    };
  }

  root.Nui = {
    SEVERITY: SEVERITY,
    rules: { js: JS_RULES, html: HTML_RULES, css: CSS_RULES },
    kindOf: kindOf,
    scan: scan,
    clean: clean
  };
})(typeof window !== 'undefined' ? window : globalThis);
