/* app.js — câblage de l'interface (aucune requête réseau, tout est local). */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  /* Garde-fou anti-boucle, pas une limite métier : le lot est traité en séquence,
     fichier par fichier, et la mémoire est libérée aussitôt. */
  var MAX_FILES = 20000;
  var MAX_FILE_BYTES = 96 * 1024 * 1024;
  var MAX_CHUNKS_PER_FILE = 12;

  function fmtBytes(n) {
    if (n < 1024) return n + ' o';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' Ko';
    return (n / (1024 * 1024)).toFixed(2) + ' Mo';
  }

  /* ------------------------------- onglets ------------------------------- */
  document.querySelectorAll('.tablist').forEach(function (list) {
    var group = list.dataset.tabs;
    list.addEventListener('click', function (e) {
      var btn = e.target.closest('.tab');
      if (!btn || !list.contains(btn)) return;
      list.querySelectorAll('.tab').forEach(function (b) {
        var on = b === btn;
        b.classList.toggle('is-active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      document.querySelectorAll('[data-panel-group="' + group + '"]').forEach(function (p) {
        p.hidden = p.dataset.panel !== btn.dataset.tab;
      });
    });
  });

  function activateTool(name) {
    var list = document.querySelector('.tablist-main');
    var btn = list.querySelector('[data-tab="' + name + '"]');
    if (btn) btn.click();
  }

  /* ------------------------------ lecture fichiers ------------------------------ */
  function readBytes(file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(new Uint8Array(r.result)); };
      r.onerror = function () { reject(r.error || new Error('lecture impossible')); };
      r.readAsArrayBuffer(file);
    });
  }

  function readText(file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(String(r.result)); };
      r.onerror = function () { reject(r.error || new Error('lecture impossible')); };
      r.readAsText(file);
    });
  }

  function wireDrop(zoneId, inputId, handler) {
    var zone = $(zoneId);
    var input = $(inputId);
    input.addEventListener('change', function () {
      if (input.files && input.files[0]) handler(input.files[0]);
      input.value = '';
    });
    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault();
        zone.classList.add('is-drag');
      });
    });
    ['dragleave', 'dragend', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault();
        zone.classList.remove('is-drag');
      });
    });
    zone.addEventListener('drop', function (e) {
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) handler(f);
    });
  }

  /* --------------------------------- copie --------------------------------- */
  function copyText(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = 'Copié';
      setTimeout(function () { btn.textContent = old; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) { /* ignoré */ }
      document.body.removeChild(ta);
      done();
    }
  }

  function download(name, text) {
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    if (window.CypherBridge && window.CypherBridge.save) { window.CypherBridge.save(name, blob); return; }
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function srcBaseName(name) {
    return String(name || 'chunk').replace(/\.(luac?|fxap|out|bin|lua)$/i, '');
  }

  /* Chemin relatif réel d'une entrée : on retire le préfixe d'archive
     (« dossier.zip › ») et les séparateurs Windows, mais on garde les
     sous-dossiers de la ressource — sans eux, un script déplacé à la racine
     ne correspond plus à la ligne de son manifeste et FiveM le cherche en vain. */
  function relPathOf(p) {
    return String(p || 'fichier').split(' › ').pop().replace(/\\/g, '/').replace(/^\/+/, '');
  }

  function stripExt(p) {
    return String(p).replace(/\.[A-Za-z0-9]{1,6}$/, '');
  }

  function safeFileName(path, index) {
    var base = srcBaseName(String(path).split(' › ').pop());
    return base.replace(/[^A-Za-z0-9._-]+/g, '_') + (index ? '.' + index : '') + '.recovered.lua';
  }

  /* ------------------------------ rendu bytecode ------------------------------ */
  var state = { code: '', disasm: '', name: 'chunk.luac' };

  function renderBytecode(file, bytes, parsed) {
    var stats = Lua54.countStats(parsed.main);
    var header = parsed.header;
    state.name = file.name;
    $('bytecode-result').hidden = false;

    $('bc-name').textContent = file.name;
    $('bc-sub').textContent = fmtBytes(bytes.length) + ' · ' + parsed.bytesUsed + ' octets consommés · ' +
      (parsed.hasDebugInfo ? 'informations de debug présentes' : 'chunk strippé (aucun debug)');

    var dec = Lua54.decompile(parsed.main, { fileName: file.name });
    state.code = dec.code;
    state.disasm = Lua54.disassemble(parsed.main);

    $('bc-source').textContent = dec.code;
    $('bc-disasm').textContent = state.disasm;
    $('bc-term-title').textContent = srcBaseName(file.name) + '.decompiled.lua';

    var cards = [
      ['version', 'Lua ' + header.version],
      ['ordre des octets', header.littleEndian ? 'petit-boutiste' : 'grand-boutiste'],
      ['prototypes', stats.prototypes],
      ['instructions', stats.instructions],
      ['constantes', stats.constants],
      ['chaînes', stats.strings],
      ['upvalues', stats.upvalues],
      ['digest', parsed.hasDebugInfo ? 'avec debug' : 'strippé']
    ];
    var dl = $('bc-stats');
    dl.textContent = '';
    cards.forEach(function (c) {
      var d = document.createElement('div');
      var dt = document.createElement('dt');
      dt.textContent = c[0];
      var dd = document.createElement('dd');
      dd.textContent = c[1];
      d.appendChild(dt);
      d.appendChild(dd);
      dl.appendChild(d);
    });

    var notes = $('bc-notes');
    notes.textContent = '';
    var all = parsed.warnings.concat(dec.warnings);
    notes.hidden = !all.length;
    all.forEach(function (w) {
      var li = document.createElement('li');
      li.className = 'warn';
      li.textContent = w;
      notes.appendChild(li);
    });

    renderConstants(parsed.main);
    $('bc-copy').disabled = false;
    $('bc-download').disabled = false;
  }

  function renderConstants(main) {
    var table = $('bc-consts');
    table.textContent = '';
    var head = document.createElement('thead');
    var hr = document.createElement('tr');
    ['prototype', '#', 'type', 'valeur'].forEach(function (t) {
      var th = document.createElement('th');
      th.textContent = t;
      hr.appendChild(th);
    });
    head.appendChild(hr);
    table.appendChild(head);

    var body = document.createElement('tbody');
    var rows = 0;
    Lua54.walkProtos(main, function (proto, path) {
      for (var i = 0; i < proto.constants.length && rows < 900; i++) {
        var c = proto.constants[i];
        var tr = document.createElement('tr');
        var cells = [];
        cells.push(['pc', path]);
        cells.push(['pc', 'K' + i]);
        cells.push(['ty', c.type]);
        if (c.type === 'string') {
          cells.push(['', c.printable ? Lua54.quoteLua(c.value) : '«binaire ' + (c.raw ? c.raw.length : 0) + ' octets»']);
        } else {
          cells.push(['', c.type === 'nil' ? 'nil' : String(c.value)]);
        }
        cells.forEach(function (cell) {
          var td = document.createElement('td');
          if (cell[0]) td.className = cell[0];
          td.textContent = cell[1];
          tr.appendChild(td);
        });
        body.appendChild(tr);
        rows++;
      }
    });
    table.appendChild(body);
  }

  /* ------------------------------ rendu FXAP ------------------------------ */
  var fxapBytes = null;

  function renderReport(file, bytes, report, error) {
    fxapBytes = bytes;
    var host = $('fxap-result');
    host.textContent = '';
    host.hidden = false;

    var head = document.createElement('div');
    head.className = 'report-head';
    var verdict = document.createElement('span');
    verdict.className = 'verdict ' + (report.verdict === 'fxap' ? 'is-fxap'
      : (report.verdict === 'bytecode' || report.verdict === 'source') ? 'is-ok' : 'is-warn');
    verdict.textContent = report.verdictLabel;
    var name = document.createElement('span');
    name.className = 'file-sub';
    name.textContent = file.name + ' · ' + fmtBytes(bytes.length) + ' · entropie ' + report.entropy.toFixed(2) + ' bits/octet';
    head.appendChild(verdict);
    head.appendChild(name);
    host.appendChild(head);

    var stats = document.createElement('dl');
    stats.className = 'stats';
    [
      ['taille', fmtBytes(report.size)],
      ['entropie', report.entropy.toFixed(2)],
      ['signature FXAP', report.markers.length ? 'oui' : 'non'],
      ['chunks Lua', String(report.embeddedChunks.length)],
      ['chaînes', String(report.strings.length)]
    ].forEach(function (c) {
      var d = document.createElement('div');
      var dt = document.createElement('dt');
      dt.textContent = c[0];
      var dd = document.createElement('dd');
      dd.textContent = c[1];
      d.appendChild(dt);
      d.appendChild(dd);
      stats.appendChild(d);
    });
    host.appendChild(stats);

    if (error) {
      var en = document.createElement('ul');
      en.className = 'notes';
      var li0 = document.createElement('li');
      li0.className = 'info';
      li0.textContent = 'Lecture directe du chunk impossible : ' + error.message;
      en.appendChild(li0);
      host.appendChild(en);
    }

    var notes = document.createElement('ul');
    notes.className = 'notes';
    report.findings.forEach(function (f) {
      var li = document.createElement('li');
      li.className = f.level;
      li.textContent = f.text;
      notes.appendChild(li);
    });
    host.appendChild(notes);

    var dumpTitle = document.createElement('p');
    dumpTitle.className = 'file-sub';
    dumpTitle.textContent = '320 premiers octets';
    host.appendChild(dumpTitle);
    var dump = document.createElement('pre');
    dump.className = 'hexdump';
    dump.textContent = report.preview.replace(/(.{64})/g, '$1\n');
    host.appendChild(dump);

    if (report.strings.length) {
      var stTitle = document.createElement('p');
      stTitle.className = 'file-sub';
      stTitle.textContent = 'Chaînes lisibles · ' + report.strings.length;
      stTitle.style.marginTop = '22px';
      host.appendChild(stTitle);
      var box = document.createElement('div');
      box.className = 'strings';
      report.strings.slice(0, 120).forEach(function (s) {
        var codeEl = document.createElement('code');
        codeEl.textContent = '0x' + s.offset.toString(16).padStart(6, '0') + '  ' + s.value;
        box.appendChild(codeEl);
      });
      host.appendChild(box);
    }
  }

  /* ------------------------- déchiffrement avec une clé ------------------------- */
  $('keyform').addEventListener('submit', function (e) {
    e.preventDefault();
    var out = $('key-result');
    out.textContent = '';
    out.hidden = false;

    if (!fxapBytes) {
      if (lastFxap) {
        if (!fxapKey()) {
          out.textContent = 'Clé invalide : 16, 24 ou 32 octets attendus (hexadécimal ou base64), IV de 16 octets si fourni.';
          return;
        }
        out.textContent = 'Nettoyage du lot avec la clé…';
        handleFxapBatch(lastFxap).then(function () {
          out.textContent = 'Lot analysé avec la clé : résultats ci-dessous.';
        });
        return;
      }
      out.textContent = 'Analysez d\'abord un fichier dans cet onglet (dépôt ci-dessus).';
      return;
    }
    var key = Recover.parseKey($('key-input').value);
    if (!key || [16, 24, 32].indexOf(key.length) === -1) {
      out.textContent = 'Clé invalide : 16, 24 ou 32 octets attendus (hexadécimal ou base64).';
      return;
    }
    var ivText = $('iv-input').value.trim();
    var iv = ivText ? Recover.parseKey(ivText) : null;
    if (ivText && (!iv || iv.length !== 16)) {
      out.textContent = 'IV invalide : 16 octets attendus.';
      return;
    }
    var mode = $('key-mode').value;
    out.textContent = 'Déchiffrement en cours…';

    Recover.decrypt(fxapBytes, { key: key, iv: iv, mode: mode, lua: Lua54 }).then(function (r) {
      out.textContent = '';
      if (!r.ok) {
        out.textContent = 'Échec : ' + r.reason + '. La clé ne correspond pas à cette charge utile.';
        return;
      }
      var code = r.text != null ? r.text : Lua54.decompile(r.parsed.main, { fileName: 'decrypted.luac' }).code;
      var meta = document.createElement('p');
      meta.className = 'file-sub';
      meta.textContent = 'Déchiffré · ' + (r.kind === 'source' ? 'source Lua' : 'bytecode décompilé') +
        ' · offset 0x' + r.offset.toString(16) + ' · AES-' + r.mode + ' · ' + r.ivLabel;
      var dl = document.createElement('button');
      dl.type = 'button';
      dl.className = 'btn btn-primary';
      dl.textContent = 'Télécharger .lua';
      dl.addEventListener('click', function () { download('decrypted.decompiled.lua', code); });
      var pre = document.createElement('pre');
      pre.className = 'code code-box';
      pre.textContent = code;
      out.appendChild(meta);
      out.appendChild(dl);
      out.appendChild(pre);
    });
  });

  /* ------------------------------------------------------------------ *
   * Récupération par lot : dossier, archive zip, ou plusieurs fichiers.
   * Traitement séquentiel : un fichier en mémoire à la fois.
   * ------------------------------------------------------------------ */
  var zone = $('dz-recovery');
  var progress = $('recovery-progress');

  function setProgress(text) {
    progress.hidden = !text;
    progress.textContent = text || '';
  }

  function collectDropped(dt) {
    var items = dt.items;
    if (items && items.length) {
      var entries = [];
      for (var i = 0; i < items.length; i++) {
        var entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
        if (entry) entries.push(entry);
      }
      if (entries.length) return { entries: entries, files: null };
    }
    return { entries: null, files: Array.prototype.slice.call(dt.files || []) };
  }

  function readEntry(entry) {
    return new Promise(function (resolve) {
      try {
        entry.file(function (f) { resolve(f); }, function () { resolve(null); });
      } catch (e) {
        resolve(null);
      }
    });
  }

  function readAllEntries(reader) {
    return new Promise(function (resolve) {
      var acc = [];
      var next = function () {
        reader.readEntries(function (batch) {
          if (!batch.length) return resolve(acc);
          acc = acc.concat(Array.prototype.slice.call(batch));
          next();
        }, function () { resolve(acc); });
      };
      next();
    });
  }

  async function walkEntry(entry, prefix, out, depth) {
    if (out.length >= MAX_FILES || depth > 8) return;
    if (entry.isFile) {
      var f = await readEntry(entry);
      if (f) out.push({ file: f, path: prefix + entry.name });
      return;
    }
    if (entry.isDirectory) {
      var reader = entry.createReader();
      var kids = await readAllEntries(reader);
      for (var i = 0; i < kids.length; i++) {
        await walkEntry(kids[i], prefix + entry.name + '/', out, depth + 1);
      }
    }
  }

  async function collectFromPayload(payload) {
    var out = [];
    if (payload.entries) {
      for (var i = 0; i < payload.entries.length; i++) {
        await walkEntry(payload.entries[i], '', out, 0);
      }
      return out;
    }
    (payload.files || []).forEach(function (f) {
      out.push({ file: f, path: f.webkitRelativePath || f.name });
    });
    return out;
  }

  function isArchiveName(name) {
    return /\.zip$/i.test(String(name));
  }

  /* Décompresse une archive et empile ses entrées (récursif sur les .zip). */
  async function pushArchive(queue, path, bytes, depth) {
    if (depth > 3) return 0;
    var list;
    try {
      list = await Zip.entries(bytes, { maxEntries: 5000, maxSize: MAX_FILE_BYTES });
    } catch (e) {
      return 0;
    }
    var added = 0;
    for (var i = 0; i < list.length; i++) {
      var e = list[i];
      /* Un fichier vide reste un fichier : sa présence peut être attendue
         par le manifeste, on le recopie donc tel quel. */
      if (!e.data) continue;
      var inner = path + ' › ' + e.name;
      if (isArchiveName(e.name)) {
        added += await pushArchive(queue, inner, e.data, depth + 1);
        continue;
      }
      queue.push({ path: inner, name: e.name.split('/').pop(), bytes: e.data });
      added++;
    }
    return added;
  }

  function analyzeOne(item, bytes) {
    var chunks = [];
    var res;
    try {
      res = Recover.analyze(bytes, Lua54);
    } catch (e) {
      res = { candidates: [] };
    }
    var parsed = (res.candidates || []).filter(function (c) { return c.parsed; });
    for (var i = 0; i < parsed.length && i < MAX_CHUNKS_PER_FILE; i++) {
      var c = parsed[i];
      chunks.push({
        transform: c.transform,
        offset: c.offset,
        size: c.size,
        repaired: c.repaired,
        stats: Lua54.countStats(c.parsed.main),
        code: Lua54.decompile(c.parsed.main, { fileName: item.path }).code
      });
    }
    return { path: item.path, size: bytes.length, chunks: chunks, extraChunks: Math.max(0, parsed.length - MAX_CHUNKS_PER_FILE) };
  }

  async function handleBatch(payload) {
    var host = $('recovery-result');
    host.hidden = true;

    var entries;
    try {
      setProgress('Lecture du dépôt…');
      entries = await collectFromPayload(payload);
    } catch (e) {
      setProgress('');
      host.hidden = false;
      host.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) {
      setProgress('');
      return;
    }

    var queue = entries.map(function (e) {
      return { path: e.path, name: e.file.name, file: e.file };
    });
    var results = [];
    var archives = 0;
    var bytesSeen = 0;
    var processed = 0;
    var skipped = 0;

    while (queue.length && processed < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) { continue; }
      bytesSeen += bytes.length;

      if (isArchiveName(item.name)) {
        archives++;
        setProgress('Décompression ' + item.path);
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      setProgress('Analyse ' + (processed + 1) + ' · ' + queue.length + ' en attente · ' + item.path);
      await new Promise(function (r) { setTimeout(r, 0); });

      if (bytes.length > MAX_FILE_BYTES) {
        skipped++;
        results.push({ path: item.path, size: bytes.length, chunks: [], tooBig: true });
      } else {
        results.push(analyzeOne(item, bytes));
      }
      bytes = null;
      processed++;
    }

    setProgress('');
    var withChunks = results.filter(function (r) { return r.chunks.length; });
    var chunkTotal = withChunks.reduce(function (n, r) { return n + r.chunks.length; }, 0);

    var notes = [];
    if (archives) notes.push(archives + ' archive(s) .zip décompressée(s) en mémoire, entrées imbriquées incluses.');
    if (skipped) notes.push(skipped + ' fichier(s) dépassant ' + fmtBytes(MAX_FILE_BYTES) + ' non analysé(s).');
    if (processed >= MAX_FILES) notes.push('Garde-fou de ' + MAX_FILES + ' fichiers atteint : le lot a été tronqué.');
    if (results.some(function (r) { return r.extraChunks; })) {
      notes.push('Au-delà de ' + MAX_CHUNKS_PER_FILE + ' chunks par fichier, seul le premier lot est reconstruit.');
    }

    renderBatch(results, {
      files: processed,
      bytes: bytesSeen,
      archives: archives,
      chunkTotal: chunkTotal,
      notes: notes
    });
  }

  function buildChunkCard(result, chunk, idx) {
    var card = document.createElement('article');
    card.className = 'card';
    card.style.marginBottom = '12px';

    var h = document.createElement('h3');
    h.textContent = chunk.transform + ' · offset 0x' + chunk.offset.toString(16) + ' · ' + fmtBytes(chunk.size);
    card.appendChild(h);

    var p = document.createElement('p');
    p.textContent = chunk.stats.prototypes + ' prototype(s) · ' + chunk.stats.instructions + ' instructions · ' +
      chunk.stats.constants + ' constante(s)' + (chunk.repaired ? ' · en-tête reconstruit' : '');
    card.appendChild(p);

    var actions = document.createElement('div');
    actions.className = 'result-actions';
    actions.style.marginTop = '12px';

    var view = document.createElement('button');
    view.type = 'button';
    view.className = 'btn btn-ghost';
    view.textContent = 'Voir le source';

    var dl = document.createElement('button');
    dl.type = 'button';
    dl.className = 'btn btn-primary';
    dl.textContent = 'Télécharger .lua';
    dl.addEventListener('click', function () {
      download(safeFileName(result.path, idx), chunk.code);
    });

    var pre = document.createElement('pre');
    pre.className = 'code code-box';
    pre.hidden = true;
    pre.textContent = chunk.code;

    view.addEventListener('click', function () {
      pre.hidden = !pre.hidden;
      view.textContent = pre.hidden ? 'Voir le source' : 'Masquer le source';
    });

    actions.appendChild(view);
    actions.appendChild(dl);
    card.appendChild(actions);
    card.appendChild(pre);
    return card;
  }

  function fileCard(result) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = result.path;
    var right = document.createElement('span');
    right.className = 'filebadge';
    right.textContent = result.chunks.length + ' chunk(s) · ' + fmtBytes(result.size);
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (det.open && !body.dataset.built) {
        body.dataset.built = '1';
        result.chunks.forEach(function (chunk, idx) {
          body.appendChild(buildChunkCard(result, chunk, idx));
        });
      }
    });
    det.appendChild(body);
    return det;
  }

  function renderBatch(results, meta) {
    var host = $('recovery-result');
    host.textContent = '';
    host.hidden = false;

    var withChunks = results.filter(function (r) { return r.chunks.length; });
    var without = results.filter(function (r) { return !r.chunks.length; });

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (meta.chunkTotal ? 'is-ok' : 'is-warn');
    badge.textContent = meta.chunkTotal
      ? meta.chunkTotal + ' chunk(s) récupéré(s) dans ' + withChunks.length + ' fichier(s)'
      : 'aucun chunk récupérable';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.files + ' fichier(s) analysé(s) · ' + fmtBytes(meta.bytes) +
      (meta.archives ? ' · ' + meta.archives + ' archive(s)' : '');
    head.appendChild(badge);
    head.appendChild(sub);
    host.appendChild(head);

    if (meta.notes.length) {
      var notes = document.createElement('ul');
      notes.className = 'notes';
      meta.notes.forEach(function (n) {
        var li = document.createElement('li');
        li.className = 'info';
        li.textContent = n;
        notes.appendChild(li);
      });
      host.appendChild(notes);
    }

    if (withChunks.length) {
      var list = document.createElement('div');
      list.className = 'filelist';
      withChunks.forEach(function (r) { list.appendChild(fileCard(r)); });
      host.appendChild(list);
    } else {
      var empty = document.createElement('p');
      empty.className = 'limit';
      empty.textContent = 'Aucun chunk Lua dans ce dépôt. Les fichiers chiffrés (escrow FXAP) restent illisibles tant que la charge utile n\'est pas déchiffrée : passez par l\'onglet « Clean FXAP & Mapping » si vous disposez de la clé, ou déposez le bytecode produit par votre propre outil.';
      host.appendChild(empty);
    }

    if (without.length) {
      var det = document.createElement('details');
      det.className = 'filecard';
      var sum = document.createElement('summary');
      var l = document.createElement('span');
      l.className = 'fname';
      l.textContent = without.length + ' fichier(s) sans bytecode exploitable';
      sum.appendChild(l);
      det.appendChild(sum);
      var body = document.createElement('div');
      body.className = 'filebody';
      without.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'filerow';
        var nm = document.createElement('span');
        nm.textContent = r.path + (r.tooBig ? ' (trop volumineux)' : '');
        var sz = document.createElement('span');
        sz.className = 'filebadge';
        sz.textContent = fmtBytes(r.size);
        row.appendChild(nm);
        row.appendChild(sz);
        body.appendChild(row);
      });
      det.appendChild(body);
      host.appendChild(det);
    }
  }

  ['dragenter', 'dragover'].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault();
      zone.classList.add('is-drag');
    });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault();
      zone.classList.remove('is-drag');
    });
  });
  zone.addEventListener('drop', function (e) {
    e.preventDefault();
    zone.classList.remove('is-drag');
    handleBatch(collectDropped(e.dataTransfer));
  });

  $('file-recovery').addEventListener('change', function (e) {
    var files = Array.prototype.slice.call(e.target.files || []);
    if (files.length) handleBatch({ entries: null, files: files });
    e.target.value = '';
  });

  $('dir-recovery').addEventListener('change', function (e) {
    var files = Array.prototype.slice.call(e.target.files || []);
    if (files.length) handleBatch({ entries: null, files: files });
    e.target.value = '';
  });

  /* ------------------------------ zones simples ------------------------------ */
  wireDrop('dz-bytecode', 'file-bytecode', function (file) {
    readBytes(file).then(function (bytes) {
      try {
        var parsed = Lua54.parseChunk(bytes);
        renderBytecode(file, bytes, parsed);
      } catch (err) {
        var report = Fxap.analyze(bytes, file.name);
        renderReport(file, bytes, report, err);
        activateTool('fxap');
      }
    }).catch(function (err) {
      window.alert('Lecture du fichier impossible : ' + err.message);
    });
  });

  /* ------------------------------------------------------------------ *    * Clean FXAP & Mapping : analyse par lot, retrait de l'en-tête FXAP, export marqué.
   * ------------------------------------------------------------------ */
  var lastFxap = null;
  var PASSTHROUGH_MAX = 256 * 1024 * 1024;
  var RAW_BUDGET = 1024 * 1024 * 1024;
  var fxapRawBudget = RAW_BUDGET;

  function downloadRaw(name, bytes) {
    var blob = new Blob([bytes], { type: 'application/octet-stream' });
    var out = String(name).split('/').pop() || 'asset.bin';
    if (window.CypherBridge && window.CypherBridge.save) { window.CypherBridge.save(out, blob); return; }
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = out;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function fxapKey() {
    var raw = $('key-input').value.trim();
    if (!raw) return null;
    var key = Recover.parseKey(raw);
    if (!key || [16, 24, 32].indexOf(key.length) === -1) return null;
    var ivRaw = $('iv-input').value.trim();
    var iv = ivRaw ? Recover.parseKey(ivRaw) : null;
    if (ivRaw && (!iv || iv.length !== 16)) return null;
    return { key: key, iv: iv, mode: $('key-mode').value };
  }

  /* Tout fichier texte (Lua, manifest, cfg…) est une source exploitable tel quel.
     On ne se fie pas aux mots-clés : un fxmanifest n'en contient aucun. */
  function textSource(bytes, name) {
    var n = Math.min(bytes.length, 262144);
    for (var i = 0; i < n; i++) if (bytes[i] === 0) return null;
    var text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { return null; }
    if (!text.trim()) return null;
    var printable = text.replace(/[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]/g, '').length;
    if (printable / text.length < 0.93) return null;
    var ext = (/\.([A-Za-z0-9]+)$/.exec(String(name)) || [])[1];
    ext = ext ? ext.toLowerCase() : '';
    var lua = ext === 'lua' || ext === 'luau' || /(^|[\s;(])--/.test(text);
    return { text: text, lua: lua, ext: ext };
  }

  /* Un script .lua sans mot-clé connu était classé « binaire » : un fichier
     texte lisible ne doit jamais être annoncé comme illisible. */
  function refineFxapReport(report, bytes, path) {
    if (report.verdict !== 'binaire') return report;
    var src = textSource(bytes, path);
    if (!src) return report;
    report.verdict = 'source';
    report.verdictLabel = src.lua ? 'Source Lua en clair (.lua)' : 'Fichier texte en clair';
    report.findings = report.findings.filter(function (f) {
      return f.text.indexOf('Ni signature Lua ni en-tête FXAP') !== 0;
    }).concat([{
      level: 'ok',
      text: 'Fichier texte lisible : aucune protection FXAP, il est recopié à l’identique dans l’archive.'
    }]);
    return report;
  }

  /* Retire l'en-tête du conteneur FXAP : la charge utile commence au premier
     chunk Lua, s'il y en a un. Le fichier .fxap lui-même n'est jamais exporté. */
  function fxapPayload(bytes) {
    for (var i = 0; i + 3 < bytes.length; i++) {
      if (bytes[i] === 0x1b && bytes[i + 1] === 0x4c && bytes[i + 2] === 0x75 && bytes[i + 3] === 0x61) {
        return i === 0 ? bytes : bytes.subarray(i);
      }
    }
    return null;
  }

  /* Le nom d'origine est conservé : un fxmanifest.lua nettoyé reste fxmanifest.lua,
     c'est ce que le fxmanifest et les scripts attendent. */
  function chunkOutName(chunk, base, idx) {
    if (chunk.lua === true) return base + '.lua';
    if (chunk.lua === false) return base + (chunk.ext ? '.' + chunk.ext : '.txt');
    return base + '.chunk' + (idx + 1) + '.lua';
  }

  function markerOffset(bytes) {
    var n = Math.min(bytes.length - 4, 4096);
    for (var i = 0; i <= n; i++) {
      if (bytes[i] === 0x46 && bytes[i + 1] === 0x58 && bytes[i + 2] === 0x41 && bytes[i + 3] === 0x50) return i;
    }
    return -1;
  }

  /* Une charge utile texte doit ressembler à du Lua, pas à des métadonnées
     JSON ou à un fragment d'en-tête qui se décoderait par hasard. */
  function looksLuaBody(text) {
    var t = String(text).trim();
    if (t.length < 24) return false;
    if (/^[{\[]/.test(t) && /[}\]]$/.test(t)) return false;
    return /[=(){}\[\]]|--|\bend\b|\breturn\b|\blocal\b|\bfunction\b/.test(t);
  }

  async function inflateTry(bytes) {
    if (typeof DecompressionStream === 'undefined' || !bytes.length) return null;
    var formats = ['gzip', 'deflate', 'deflate-raw'];
    for (var i = 0; i < formats.length; i++) {
      try {
        var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(formats[i]));
        var buf = await new Response(stream).arrayBuffer();
        if (buf.byteLength) return new Uint8Array(buf);
      } catch (e) { /* on essaie le format suivant */ }
    }
    return null;
  }

  /* Beaucoup de conteneurs .lua estampillés FXAP ne chiffrent rien : la source
     est posée en clair, ou simplement compressée, derrière l'en-tête. On la
     récupère sans clé. Une charge utile réellement chiffrée reste illisible. */
  async function fxapTail(bytes, name) {
    var at = markerOffset(bytes);
    var base = at === -1 ? 0 : at + 4;
    var offsets = [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 512];
    var starts = [];
    offsets.forEach(function (d) {
      var off = base + d;
      if (off > 0 && off < bytes.length - 24) starts.push(off);
    });

    for (var s = 0; s < starts.length; s++) {
      var src = textSource(bytes.subarray(starts[s]), name);
      if (src && looksLuaBody(src.text)) {
        return {
          offset: starts[s],
          code: src.text,
          lua: src.lua,
          ext: src.ext,
          transform: 'charge utile FXAP en clair (offset 0x' + starts[s].toString(16) + ')'
        };
      }
    }

    for (var i = 0; i < starts.length; i++) {
      if (bytes.length - starts[i] < 16) continue;
      var inflated = await inflateTry(bytes.subarray(starts[i]));
      if (!inflated) continue;
      var txt = textSource(inflated, name);
      if (txt && looksLuaBody(txt.text)) {
        return {
          offset: starts[i],
          code: txt.text,
          lua: txt.lua,
          ext: txt.ext,
          transform: 'charge utile FXAP compressée (zlib/gzip)'
        };
      }
      if (inflated.length > 4 && inflated[0] === 0x1b && inflated[1] === 0x4c) {
        return {
          offset: starts[i],
          bytes: inflated,
          transform: 'bytecode Lua compressé dans le conteneur'
        };
      }
    }
    return null;
  }

  async function fxapChunks(bytes, key, name) {
    var chunks = [];

    if (key) {
      try {
        var d = await Recover.decrypt(bytes, { key: key.key, iv: key.iv, mode: key.mode, lua: Lua54 });
        if (d.ok) {
          if (d.kind === 'source' && d.text != null) {
            chunks.push({
              transform: 'AES-' + d.mode + ' · offset 0x' + d.offset.toString(16) + ' · ' + d.ivLabel,
              offset: d.offset,
              size: d.data.length,
              stats: null,
              code: d.text,
              decrypted: true,
              lua: true,
              ext: 'lua'
            });
          } else {
            chunks.push({
              transform: 'AES-' + d.mode + ' · offset 0x' + d.offset.toString(16),
              offset: d.offset,
              size: d.parsed.bytesUsed,
              stats: Lua54.countStats(d.parsed.main),
              code: Lua54.decompile(d.parsed.main, { fileName: 'decrypted' }).code,
              decrypted: true,
              lua: true,
              ext: 'lua'
            });
          }
          return chunks;
        }
      } catch (e) {
        /* on retombe sur la récupération */
      }
    }

    if (bytes.length > 4 && bytes[0] === 0x1b && bytes[1] === 0x4c && bytes[2] === 0x75 && bytes[3] === 0x61) {
      try {
        var direct = Lua54.parse(bytes);
        if (direct && direct.main) {
          chunks.push({
            transform: 'bytecode Lua 5.4 direct',
            offset: 0,
            size: bytes.length,
            stats: Lua54.countStats(direct.main),
            code: Lua54.decompile(direct.main, { fileName: 'chunk' }).code,
            decrypted: false
          });
          return chunks;
        }
      } catch (e) {
        /* on retombe sur la récupération */
      }
    }

    var src = textSource(bytes, name);
    if (src) {
      chunks.push({
        transform: src.lua ? 'source Lua en clair' : 'fichier texte en clair',
        offset: 0,
        size: bytes.length,
        stats: null,
        code: src.text,
        decrypted: false,
        lua: src.lua,
        ext: src.ext
      });
      return chunks;
    }

    var tail = await fxapTail(bytes, name);
    if (tail) {
      if (tail.bytes) {
        try {
          var packed = Lua54.parse(tail.bytes);
          if (packed && packed.main) {
            chunks.push({
              transform: tail.transform,
              offset: tail.offset,
              size: tail.bytes.length,
              stats: Lua54.countStats(packed.main),
              code: Lua54.decompile(packed.main, { fileName: 'chunk' }).code,
              decrypted: true
            });
            return chunks;
          }
        } catch (e) { /* on continue sur la récupération classique */ }
      } else {
        chunks.push({
          transform: tail.transform,
          offset: tail.offset,
          size: bytes.length - tail.offset,
          stats: null,
          code: tail.code,
          decrypted: true,
          lua: tail.lua,
          ext: tail.ext
        });
        return chunks;
      }
    }

    var res;
    try { res = Recover.analyze(bytes, Lua54); } catch (e) { res = { candidates: [] }; }
    (res.candidates || []).filter(function (c) { return c.parsed; }).slice(0, 12).forEach(function (c) {
      chunks.push({
        transform: c.transform,
        offset: c.offset,
        size: c.size,
        stats: Lua54.countStats(c.parsed.main),
        code: Lua54.decompile(c.parsed.main, { fileName: 'chunk' }).code,
        decrypted: false
      });
    });
    return chunks;
  }

  function stampFxap(code, lua) {
    if (lua === false) return code;
    var when = new Date().toLocaleString('fr-FR');
    return '-- Nettoyé par CypherDecrypter · Clean FXAP & Mapping · ' + when + '\n' +
      '-- Source extraite du conteneur : relisez-la avant de l’utiliser.\n\n' + code;
  }

  function fxapCard(result) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = result.path;
    var right = document.createElement('span');
    right.className = 'filebadge';
    right.textContent = result.report.verdictLabel + ' · ' + result.report.entropy.toFixed(2) + ' b/o · ' +
      result.chunks.length + ' chunk(s)' +
      (result.plain ? ' · déjà en clair, non retouché'
        : result.escrowed ? ' · conteneur chiffré conservé tel quel'
          : result.raw ? ' · recopié' : '');
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (!det.open || det.dataset.built) return;
      det.dataset.built = '1';

      var notes = document.createElement('ul');
      notes.className = 'notes';
      result.report.findings.forEach(function (f) {
        var li = document.createElement('li');
        li.className = f.level;
        li.textContent = f.text;
        notes.appendChild(li);
      });
      if (result.keyed) {
        var ok = document.createElement('li');
        ok.className = 'ok';
        ok.textContent = 'Charge utile déchiffrée avec la clé fournie. Source reconstruite ci-dessous.';
        notes.appendChild(ok);
      }
      body.appendChild(notes);

      if (result.raw) {
        var rowRaw = document.createElement('div');
        rowRaw.className = 'filerow';
        var nmRaw = document.createElement('span');
        nmRaw.textContent = 'recopié à l’identique · ' + fmtBytes(result.raw.length);
        var dlRaw = document.createElement('button');
        dlRaw.type = 'button';
        dlRaw.className = 'btn btn-ghost';
        dlRaw.textContent = 'Télécharger';
        dlRaw.addEventListener('click', function () {
          downloadRaw(String(result.path).split(' › ').pop(), result.raw);
        });
        rowRaw.appendChild(nmRaw);
        rowRaw.appendChild(dlRaw);
        body.appendChild(rowRaw);
      }

      if (!result.chunks.length) {
        var none = document.createElement('p');
        none.className = 'limit';
        none.textContent = result.plain
          ? 'Ce fichier n’était pas chiffré par FXAP : il est recopié tel quel, sans nettoyage ni renommage, pour ne pas abîmer une ressource qui fonctionnait déjà.'
          : result.raw
          ? 'Aucune source à extraire ici : le fichier est recopié tel quel dans l’archive pour que la ressource reste complète.'
          : result.report.verdict === 'fxap'
            ? 'L’en-tête FXAP est retiré et le conteneur n’est pas exporté. Sa charge utile est chiffrée : fournissez la clé de votre ressource ci-dessous, ou déposez le bytecode produit par votre propre décrypteur dans « Récupération ».'
            : 'Aucune source exploitable : fournissez la clé de votre ressource ci-dessous, ou passez le fichier à votre propre décrypteur puis déposez le bytecode dans « Récupération ».';
        body.appendChild(none);
        return;
      }

      result.chunks.forEach(function (chunk, idx) {
        var row = document.createElement('div');
        row.className = 'filerow';
        var nm = document.createElement('span');
        nm.textContent = chunk.transform +
          (chunk.stats ? ' · ' + chunk.stats.instructions + ' instruction(s)' : '') +
          ' · ' + fmtBytes(chunk.size);
        var dl = document.createElement('button');
        dl.type = 'button';
        dl.className = 'btn btn-ghost';
        dl.textContent = 'Télécharger';
        dl.addEventListener('click', function () {
          var base = srcBaseName(String(result.path).split(' › ').pop());
          download(chunkOutName(chunk, base, idx), stampFxap(chunk.code, chunk.lua));
        });
        row.appendChild(nm);
        row.appendChild(dl);
        body.appendChild(row);
      });
    });

    det.appendChild(body);
    return det;
  }

  var MAP_FILE_RE = /\.(?:ymap|ytyp|ybn|ydr|ydd|ytd|ymt|yft|ycd|ypt)$/i;

  function globRe(glob) {
    var g = String(glob).replace(/\\/g, '/').replace(/^\.?\//, '');
    var out = '^';
    for (var i = 0; i < g.length; i++) {
      var c = g[i];
      if (c === '*' && g[i + 1] === '*') {
        if (g[i + 2] === '/') { out += '(?:[^/]+/)*'; i += 2; } else { out += '.*'; i += 1; }
      } else if (c === '*') out += '[^/]*';
      else if (c === '?') out += '[^/]';
      else out += /[\\^$.*+?()[\]{}|]/.test(c) ? '\\' + c : c;
    }
    return new RegExp(out + '$', 'i');
  }

  /* Un fxmanifest recopié tel quel réclame souvent des fichiers que le conteneur
     FXAP fournissait (motifs à joker du type  ** / *.ymap  ) : FiveM lève alors
     « could not find file ». On aligne donc le manifeste sur ce que l'archive
     contient vraiment, et on marque une ressource mapping. */
  /* Extensions d'assets reconnues dans un manifeste : tout chemin portant l'une
     d'elles et absent de l'export est une référence morte, celle que FiveM
     signale au démarrage par « could not find file ». */
  var ASSET_EXT_RE = /\.(?:lua|luac|meta|xml|ymap|ytyp|ybn|ydr|ydd|ytd|ymt|ymf|yft|ycd|ypt|ydt|gxt|gtxd|dat|rel|blob|nod|awc|oiv|json|txt|cfg|ini|csv|html?|css|js|png|jpe?g|dds|webp|svg|mp3|ogg|wav)$/i;

  function fixManifest(text, dir, allPaths) {
    var rel = allPaths.map(function (p) {
      var s = String(p).replace(/\\/g, '/');
      if (dir && s.indexOf(dir + '/') === 0) s = s.slice(dir.length + 1);
      return s;
    });
    var mapping = rel.some(function (p) { return MAP_FILE_RE.test(p); });
    var out = [];
    var notes = [];

    function exists(v) {
      return rel.some(function (p) { return globRe(v).test(p); });
    }

    String(text).split('\n').forEach(function (line) {
      var trimmed = line.trim();
      if (/^--/.test(trimmed)) { out.push(line); return; }

      if (/\.fxap\b/i.test(line)) {
        notes.push('référence .fxap retirée');
        out.push('-- retiré par CypherDecrypter (conteneur FXAP supprimé) : ' + trimmed.replace(/,\s*$/, ''));
        return;
      }

      var quoted = line.match(/(['"])([^'"]+)\1/g) || [];
      var paths = quoted.map(function (q) { return q.slice(1, -1); })
        .filter(function (v) { return ASSET_EXT_RE.test(v) && !/\s/.test(v); });
      var missing = paths.filter(function (v) { return !exists(v); });

      var emit = line;
      if (missing.length) {
        var structural = paths.length > 1 || /[{}[\]]/.test(line);
        if (structural) {
          /* On retire la seule entrée morte en gardant la ligne — et donc la
             table — syntaxiquement valide. */
          emit = line.replace(/(['"])([^'"]+)\1\s*,?\s*/g, function (m, q, v) {
            if (!ASSET_EXT_RE.test(v) || /\s/.test(v)) return m;
            return exists(v) ? m : '';
          })
            .replace(/,\s*([}\]])/g, '$1')
            .replace(/,\s*$/, '');
          notes.push(missing.length + ' référence(s) introuvable(s) retirée(s) (' + trimmed + ')');
        } else {
          emit = '-- retiré par CypherDecrypter (aucun fichier correspondant dans l’export) : ' + trimmed.replace(/,\s*$/, '');
          notes.push('entrée sans fichier dans l’export neutralisée (' + trimmed + ')');
        }
      }
      out.push(emit);
    });

    var code = out.join('\n');
    if (mapping && !/this_is_a_map/.test(code)) {
      code = code.replace(/\n*$/, '\n') + "this_is_a_map 'yes' -- ajouté : ressource mapping (stream .ymap/.ytyp)\n";
      notes.push("this_is_a_map 'yes' ajouté (mapping détecté)");
    }
    return { code: code, notes: notes, mapping: mapping };
  }

  function exportFxapZip(results) {
    var when = new Date().toLocaleString('fr-FR');
    var used = Object.create(null);
    var plan = [];
    var lines = ['CypherDecrypter — Clean FXAP & Mapping', 'Archive générée le ' + when, ''];
    var total = 0;
    var copied = 0;
    var plainCount = results.filter(function (r) { return r.plain; }).length;

    var blocked = [];

    results.forEach(function (r) {
      if (r.raw) {
        var rawPath = relPathOf(r.path);
        if (used[rawPath]) {
          var dotR = rawPath.lastIndexOf('.');
          rawPath = rawPath.slice(0, dotR) + '-' + used[rawPath] + rawPath.slice(dotR);
        }
        used[rawPath] = (used[rawPath] || 1) + 1;
        plan.push({
          path: rawPath,
          bytes: r.raw,
          /* un fxmanifest déjà en clair doit aussi être réaligné sur le contenu */
          manifest: /(^|\/)fxmanifest\.lua$/i.test(rawPath)
        });
        copied++;
        lines.push('- ' + r.path + '  ' + r.report.verdictLabel + ' · entropie ' +
          r.report.entropy.toFixed(2) + ' · recopié à l’identique (' + fmtBytes(r.raw.length) + ')' +
          (r.escrowed
            ? ' — conteneur chiffré conservé : Fournir la clé pour le déchiffrer, sinon FiveM le lit lui-même'
            : r.plain ? ' — déjà en clair, non modifié' : ''));
        return;
      }

      if (!r.chunks.length) {
        blocked.push(r);
        var why = r.plain
          ? 'déjà en clair mais trop volumineux pour l’archive : récupérable via la carte'
          : r.report.verdict === 'fxap'
            ? 'conteneur retiré de l’export (charge utile chiffrée : clé requise)'
            : 'binaire trop volumineux : non recopié';
        lines.push('- ' + r.path + '  ' + r.report.verdictLabel + ' · entropie ' +
          r.report.entropy.toFixed(2) + ' · ' + why);
        return;
      }
      /* L'arborescence de la ressource est conservée : sans elle, un script
         déplacé à la racine ne correspond plus à son manifeste. */
      var base = stripExt(relPathOf(r.path)).replace(/\.clean$/, '');
      r.chunks.forEach(function (chunk, idx) {
        var path = chunkOutName(chunk, base, idx);
        /* Un manifeste décompilé doit retrouver son nom exact, sinon la ressource
           ne démarre pas et ses références ne sont jamais réalignées. */
        if (/(^|\/)fxmanifest$/i.test(base)) path = base + '.lua';
        if (used[path]) {
          var dot = path.lastIndexOf('.');
          path = path.slice(0, dot) + '-' + used[path] + path.slice(dot);
        }
        used[path] = (used[path] || 1) + 1;
        plan.push({
          path: path,
          text: stampFxap(chunk.code, chunk.lua),
          manifest: /(^|\/)fxmanifest\.lua$/i.test(path)
        });
        total++;
      });
      lines.push('- ' + r.path + '  ' + r.report.verdictLabel + ' · entropie ' +
        r.report.entropy.toFixed(2) + ' · ' + r.chunks.length + ' chunk(s)');
    });

    /* Le manifeste est aligné sur le contenu réel de l'archive : c'est ce qui
       supprime les « could not find file » sur les motifs à joker au démarrage. */
    var manifestNotes = [];
    var allPaths = plan.map(function (p) { return p.path; });
    plan.forEach(function (entry) {
      if (!entry.manifest) return;
      if (!entry.text && entry.bytes) {
        try {
          entry.text = new TextDecoder('utf-8', { fatal: true }).decode(entry.bytes);
          entry.bytes = null;
        } catch (e) {
          return;
        }
      }
      var dir = entry.path.indexOf('/') === -1 ? '' : entry.path.slice(0, entry.path.lastIndexOf('/'));
      var fixed = fixManifest(entry.text, dir, allPaths);
      entry.text = fixed.code;
      entry.manifest = false;
      var label = entry.path.slice(entry.path.lastIndexOf('/') + 1);
      if (fixed.mapping) manifestNotes.push('- ' + label + '  ressource mapping détectée');
      fixed.notes.forEach(function (n) { manifestNotes.push('- ' + label + '  ' + n); });
    });

    var files = plan;

    lines.push('', total + ' source(s) extraite(s), ' + copied + ' asset(s) recopié(s) à l’identique.' +
      (plainCount ? ' ' + plainCount + ' fichier(s) déjà en clair laissé(s) intact(s).' : ''));
    if (blocked.length) {
      lines.push(blocked.length + ' fichier(s) non inclus : voir la ligne correspondante.',
        'Une charge utile chiffrée se déchiffre avec la clé de votre ressource ci-dessus ;',
        'un asset trop volumineux se récupère depuis la carte du fichier (bouton Télécharger).');
    }
    if (manifestNotes.length) {
      lines.push('', 'Manifeste ajusté pour rester chargeable :');
      manifestNotes.forEach(function (n) { lines.push(n); });
    }
    lines.push('Marked by CypherDecrypter.');
    files.push({ path: 'CYPHERDECRYPTER.txt', text: lines.join('\n') + '\n' });

    if (window.Records) {
      var recSources = 0;
      var recEnc = 0;
      var recAssets = 0;
      results.forEach(function (r) {
        recSources += r.chunks.length;
        if (r.report.verdict === 'fxap') recEnc++;
        if (r.raw) recAssets++;
      });
      var firstPath = results.length ? String(results[0].path) : '';
      Records.add({
        kind: 'fxap',
        label: firstPath.indexOf('/') === -1 ? 'Conteneur isolé' : firstPath.split('/')[0],
        files: results.length,
        sources: recSources,
        encrypted: recEnc,
        assets: recAssets
      });
    }

    downloadZip(files, 'CypherDecrypter-clean-fxap-' + stampDate() + '.zip');
  }

  function renderFxapBatch(results, meta) {
    var host = $('fxap-result');
    host.textContent = '';
    host.hidden = false;

    var chunkTotal = results.reduce(function (n, r) { return n + r.chunks.length; }, 0);
    var rawTotal = results.filter(function (r) { return r.raw; }).length;
    var encrypted = results.filter(function (r) { return !r.chunks.length && r.report.verdict === 'fxap' && !r.plain; }).length;
    var plainTotal = results.filter(function (r) { return r.plain; }).length;
    var plainLua = results.filter(function (r) { return r.plain && /\.lua$/i.test(String(r.path)); }).length;

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (chunkTotal || rawTotal ? 'is-ok' : 'is-warn');
    badge.textContent = [
      chunkTotal ? chunkTotal + ' source(s) récupérée(s)' : '',
      rawTotal ? rawTotal + ' fichier(s) recopié(s)' : ''
    ].filter(Boolean).join(' · ') || 'aucune source récupérable';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.files + ' fichier(s) analysé(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s)' : '') +
      (meta.keyed ? ' · clé appliquée' : '') +
      (encrypted ? ' · ' + encrypted + ' conteneur(s) chiffré(s) conservé(s)' : '');
    var clean = document.createElement('button');
    clean.type = 'button';
    clean.className = 'btn btn-ok';
    clean.textContent = 'Nettoyer automatiquement (.zip)';
    clean.disabled = !results.length;
    clean.title = chunkTotal || rawTotal
      ? 'Sources nettoyées + assets (stream, etc.) recopiés à l’identique dans une archive marquée'
      : 'Aucune source récupérable : l’archive contiendra le rapport d’analyse détaillé';
    clean.addEventListener('click', function () { exportFxapZip(results); });
    head.appendChild(badge);
    head.appendChild(sub);
    head.appendChild(clean);
    host.appendChild(head);

    /* Aucun fichier ne disparaît en silence : ceux qui ne peuvent pas être
       exportés sont nommés ici, et le rapport de l'archive les liste aussi. */
    var omitted = results.filter(function (r) { return !r.chunks.length && !r.raw; });
    if (omitted.length) {
      var omitUl = document.createElement('ul');
      omitUl.className = 'notes';
      var omitLi = document.createElement('li');
      omitLi.className = 'warn';
      omitLi.textContent = omitted.length + ' fichier(s) ne peuvent pas être exportés (lecture impossible ou budget mémoire dépassé) : ' +
        omitted.slice(0, 8).map(function (r) { return String(r.path).split(' › ').pop(); }).join(', ') +
        (omitted.length > 8 ? '…' : '') + ' — relancez-les seuls pour les récupérer.';
      omitUl.appendChild(omitLi);
      host.appendChild(omitUl);
    }

    var keptEnc = results.filter(function (r) { return r.escrowed; }).length;
    if (keptEnc) {
      var encNotes = document.createElement('ul');
      encNotes.className = 'notes';
      var encLi = document.createElement('li');
      encLi.className = 'warn';
      encLi.textContent = keptEnc + ' conteneur(s) FXAP encore chiffré(s) sont recopiés tels quels sous leur nom d’origine : ' +
        'le manifeste garde ainsi ses lignes client_script / server_script et FiveM charge ces fichiers lui-même. ' +
        'Avec la clé de la ressource, ils seraient déchiffrés et remplacés par leur source.';
      encNotes.appendChild(encLi);
      host.appendChild(encNotes);
    }

    if (plainTotal) {
      var plainNotes = document.createElement('ul');
      plainNotes.className = 'notes';
      var plainLi = document.createElement('li');
      plainLi.className = 'warn';
      plainLi.textContent = plainTotal + ' fichier(s) étaient déjà en clair (aucun conteneur FXAP)' +
        (plainLua ? ', dont ' + plainLua + ' source(s) .lua' : '') +
        ' : laissés intacts, sans nettoyage ni renommage, et recopiés sous leur nom d’origine.';
      plainNotes.appendChild(plainLi);
      host.appendChild(plainNotes);
    }

    if (!results.length) {
      var empty = document.createElement('p');
      empty.className = 'limit';
      empty.textContent = 'Aucun fichier exploitable dans ce dépôt.';
      host.appendChild(empty);
      return;
    }

    var list = document.createElement('div');
    list.className = 'filelist';
    results.forEach(function (r) { list.appendChild(fxapCard(r)); });
    host.appendChild(list);
  }

  async function handleFxapBatch(payload) {
    var host = $('fxap-result');
    var prog = $('fxap-progress');
    host.hidden = true;
    host.textContent = '';
    lastFxap = payload;
    fxapRawBudget = RAW_BUDGET;

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var key = fxapKey();
    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var results = [];
    var done = 0;
    var skipped = 0;

    while (queue.length && done < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      /* Un gros asset n'est plus écarté de l'export : on borne seulement
         l'analyse (coûteuse) à son début, le fichier entier reste recopié. */
      var examined = bytes.length > MAX_FILE_BYTES ? bytes.subarray(0, MAX_FILE_BYTES) : bytes;

      prog.textContent = 'Analyse ' + (done + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var report = refineFxapReport(Fxap.analyze(examined, item.path), examined, item.path);
      var isFxap = report.verdict === 'fxap';
      var chunks = await fxapChunks(examined, key, item.path);

      if (isFxap && !chunks.length) {
        var payload = fxapPayload(examined);
        if (payload && payload !== examined) chunks = await fxapChunks(payload, key, item.path);
      }

      /* Seul un conteneur FXAP est déchiffré. Un fichier déjà en clair (source
         Lua lisible) n'est ni nettoyé ni renommé : il est recopié tel quel et
         simplement signalé, pour ne pas abîmer une ressource qui marchait. */
      var plain = !isFxap && chunks.length > 0 && chunks.every(function (c) {
        return typeof c.lua === 'boolean';
      });
      if (plain) chunks = [];

      /* Un conteneur chiffré sans clé est conservé tel quel sous son nom
         d'origine : sans lui, le manifeste perd ses lignes client_script /
         server_script et la ressource démarre sans aucun script. FiveM sait
         lire un fichier escrow à l'exécution, un script absent non. */
      var keepEncrypted = isFxap && !chunks.length && !/\.fxap$/i.test(item.path);

      var raw = null;
      if ((!isFxap && !chunks.length || keepEncrypted) &&
          bytes.length <= PASSTHROUGH_MAX && bytes.length <= fxapRawBudget) {
        raw = bytes;
        fxapRawBudget -= bytes.length;
      }
      bytes = null;

      results.push({
        path: item.path,
        report: report,
        chunks: chunks,
        raw: raw,
        plain: plain,
        escrowed: !!(keepEncrypted && raw),
        keyed: !!(key && chunks.length && chunks[0].decrypted)
      });
      done++;
    }

    prog.hidden = true;
    renderFxapBatch(results, { files: done, skipped: skipped, keyed: !!key });
  }

  /* ------------------------------------------------------------------ *
   * Vérification Escrow : ne touche à rien. Dit seulement si le dépôt
   * contient un conteneur .fxap et si sa charge utile est déjà lisible.
   * ------------------------------------------------------------------ */
  async function escrowState(bytes, path) {
    var report = Fxap.analyze(bytes, path);
    if (report.verdict !== 'fxap') {
      var isBytecode = bytes.length > 4 && bytes[0] === 0x1b && bytes[1] === 0x4c && bytes[2] === 0x75 && bytes[3] === 0x61;
      var src = isBytecode ? null : textSource(bytes, path);
      var kind = isBytecode ? 'bytecode' : src ? (src.lua ? 'lua' : 'texte') : 'binaire';
      return {
        report: report,
        fxap: false,
        decrypted: true,
        kind: kind,
        label: kind === 'lua' ? 'aucun .fxap · source .lua en clair'
          : kind === 'bytecode' ? 'aucun .fxap · bytecode Lua lisible'
            : kind === 'texte' ? 'aucun .fxap · texte en clair'
              : 'aucun .fxap · asset recopié tel quel'
      };
    }

    var payload = fxapPayload(bytes);
    var clear = false;
    if (payload && payload.length > 4) {
      if (payload[0] === 0x1b && payload[1] === 0x4c && payload[2] === 0x75 && payload[3] === 0x61) clear = true;
      else if (textSource(payload, path)) clear = true;
    }
    if (!clear) {
      var tail = await fxapTail(bytes, path);
      if (tail) clear = true;
    }

    return {
      report: report,
      fxap: true,
      decrypted: clear,
      kind: clear ? 'lua' : 'chiffre',
      label: clear ? 'déjà déchiffré · rien à faire' : 'chiffré · clé de la ressource requise'
    };
  }

  function renderEscrow(rows, meta) {
    var host = $('escrow-result');
    host.textContent = '';
    host.hidden = false;

    var fxaps = rows.filter(function (r) { return r.state.fxap; });
    var still = fxaps.filter(function (r) { return !r.state.decrypted; });
    /* Tout ce qui est du Lua, source ou bytecode, est signalé même sans FXAP :
       c'est ce qui dit s'il reste quelque chose à déverrouiller. */
    var luas = rows.filter(function (r) { return r.state.kind === 'lua' || r.state.kind === 'bytecode'; }).length;

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (still.length ? 'is-warn' : 'is-ok');
    badge.textContent = (!fxaps.length
      ? 'aucun fichier .fxap'
      : still.length
        ? still.length + ' .fxap encore chiffré(s)'
        : fxaps.length + ' .fxap déjà déchiffré(s)') +
      (luas ? ' · ' + luas + ' fichier(s) Lua' : '');
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = rows.length + ' fichier(s) inspecté(s)' +
      (luas ? ' · ' + luas + ' fichier(s) Lua lisible(s)' : '') +
      (meta.archives ? ' · ' + meta.archives + ' archive(s) ignorée(s)' : '') +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s)' : '');
    head.appendChild(badge);
    head.appendChild(sub);
    host.appendChild(head);

    var answer = document.createElement('p');
    answer.className = 'escrow-answer';
    answer.textContent = !rows.length
      ? 'Rien à inspecter dans ce dépôt.'
      : !fxaps.length
        ? 'Aucun conteneur FXAP : ' + (luas ? luas + ' fichier(s) Lua sont déjà lisibles (source ou bytecode), ' : 'les fichiers sont déjà en clair, ') + 'il n’y a rien à déverrouiller ici.'
        : still.length
          ? still.length + ' conteneur(s) FXAP sont encore chiffrés : leur charge utile est illisible sans la clé de la ressource.' +
            (luas ? ' Les ' + luas + ' fichier(s) Lua marqués « déjà lisible » ou « en clair » n’ont pas besoin d’être retraités.' : '')
          : 'Tous les conteneurs FXAP trouvés sont déjà déchiffrés : inutile de relancer le nettoyage.';
    host.appendChild(answer);

    if (!rows.length) return;

    var list = document.createElement('div');
    list.className = 'escrow-list';
    rows.slice(0, 300).forEach(function (r) {
      var row = document.createElement('div');
      row.className = 'escrow-row';
      var name = document.createElement('span');
      name.className = 'escrow-path';
      name.textContent = r.path;
      var chip = document.createElement('span');
      chip.className = 'escrow-state ' + (r.state.decrypted ? 'is-ok' : 'is-warn');
      chip.textContent = r.state.label;
      row.appendChild(name);
      row.appendChild(chip);
      list.appendChild(row);
    });
    host.appendChild(list);

    if (rows.length > 300) {
      var more = document.createElement('p');
      more.className = 'limit';
      more.textContent = (rows.length - 300) + ' fichier(s) supplémentaire(s) non listés — le verdict global ci-dessus en tient compte.';
      host.appendChild(more);
    }
  }

  async function handleEscrowCheck(payload) {
    var host = $('escrow-result');
    var prog = $('fxap-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) {
      prog.hidden = true;
      renderEscrow([], { archives: 0, skipped: 0 });
      return;
    }

    var rows = [];
    var archives = 0;
    var skipped = 0;
    var seen = 0;

    while (entries.length && seen < MAX_FILES) {
      var item = entries.shift();
      seen++;
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name || item.path)) {
        archives++;
        continue;
      }
      if (bytes.length > MAX_FILE_BYTES) {
        skipped++;
        continue;
      }

      prog.textContent = 'Vérification ' + (rows.length + 1) + ' · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      rows.push({ path: item.path, state: await escrowState(bytes, item.path) });
      bytes = null;
    }

    prog.hidden = true;
    renderEscrow(rows, { archives: archives, skipped: skipped });
  }

  var dzFxap = $('dz-fxap');
  ['dragenter', 'dragover'].forEach(function (ev) {
    dzFxap.addEventListener(ev, function (e) { e.preventDefault(); dzFxap.classList.add('is-drag'); });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    dzFxap.addEventListener(ev, function (e) { e.preventDefault(); dzFxap.classList.remove('is-drag'); });
  });
  dzFxap.addEventListener('drop', function (e) {
    e.preventDefault();
    dzFxap.classList.remove('is-drag');
    handleFxapBatch(collectDropped(e.dataTransfer));
  });

  ['file-fxap', 'dir-fxap'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleFxapBatch({ entries: null, files: files });
      e.target.value = '';
    });
  });

  var escrowBtn = $('escrow-btn');
  var escrowMenu = $('escrow-menu');

  function escrowMenuOpen(open) {
    escrowMenu.hidden = !open;
    escrowBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  escrowBtn.addEventListener('click', function (e) {
    e.stopPropagation();
    escrowMenuOpen(escrowMenu.hidden);
  });

  escrowMenu.addEventListener('click', function (e) {
    var choice = e.target.closest('[data-escrow-mode]');
    if (!choice) return;
    escrowMenuOpen(false);
    $(choice.getAttribute('data-escrow-mode') === 'dir' ? 'dir-escrow' : 'file-escrow').click();
  });

  document.addEventListener('click', function (e) {
    if (escrowMenu.hidden) return;
    if (escrowBtn.contains(e.target) || escrowMenu.contains(e.target)) return;
    escrowMenuOpen(false);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !escrowMenu.hidden) escrowMenuOpen(false);
  });
  ['file-escrow', 'dir-escrow'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleEscrowCheck({ entries: null, files: files });
      e.target.value = '';
    });
  });

  $('bc-copy').addEventListener('click', function () { copyText(state.code, $('bc-copy')); });
  $('bc-download').addEventListener('click', function () {
    download(srcBaseName(state.name) + '.decompiled.lua', state.code);
  });

  /* ------------------------------------------------------------------ *
   * Classement local : sessions enregistrées dans ce navigateur (records.js).
   * ------------------------------------------------------------------ */
  function recordDate(ts) {
    var d = new Date(ts);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(d.getDate()) + '/' + p(d.getMonth() + 1) + ' ' + p(d.getHours()) + 'h' + p(d.getMinutes());
  }

  function recordFloat(n) {
    return Number(n || 0).toLocaleString('fr-FR');
  }

  function renderRecords() {
    if (!window.Records) return;
    var board = $('records-board');
    if (!board) return;

    var rows = Records.list();
    var totals = Records.totals();
    $('rec-total').textContent = recordFloat(totals.score);
    $('rec-runs').textContent = recordFloat(totals.runs);
    $('rec-sources').textContent = recordFloat(totals.sources);
    $('rec-encrypted').textContent = recordFloat(totals.encrypted);
    $('rec-assets').textContent = recordFloat(totals.assets);

    var podium = $('rec-podium');
    podium.textContent = '';
    if (!rows.length) {
      var empty = document.createElement('p');
      empty.className = 'board-empty';
      empty.textContent = 'Aucune session pour l’instant : lancez un nettoyage dans un onglet, le classement se remplit tout seul.';
      podium.appendChild(empty);
    }
    rows.slice(0, 3).forEach(function (e, i) {
      var card = document.createElement('article');
      card.className = 'podium-card rank-' + (i + 1);

      var top = document.createElement('div');
      top.className = 'podium-top';
      var rank = document.createElement('span');
      rank.className = 'podium-rank';
      rank.textContent = '#' + (i + 1);
      var kind = document.createElement('span');
      kind.className = 'chip chip-kind kind-' + e.kind;
      kind.textContent = (Records.KINDS[e.kind] || {}).short || 'LOT';
      top.appendChild(rank);
      top.appendChild(kind);

      var name = document.createElement('p');
      name.className = 'podium-name';
      name.textContent = e.label;

      var score = document.createElement('p');
      score.className = 'podium-score';
      score.textContent = recordFloat(e.score);
      var unit = document.createElement('span');
      unit.textContent = ' pts';
      score.appendChild(unit);

      var meta = document.createElement('p');
      meta.className = 'podium-meta';
      meta.textContent = e.files + ' fichier(s) · ' + e.sources + ' source(s) · ' + recordDate(e.ts);

      card.appendChild(top);
      card.appendChild(name);
      card.appendChild(score);
      card.appendChild(meta);
      podium.appendChild(card);
    });

    var recent = $('rec-recent');
    recent.textContent = '';
    if (!rows.length) {
      var hint = document.createElement('p');
      hint.className = 'board-empty';
      hint.textContent = 'Le barème récompense les sources récupérées, les conteneurs déchiffrés et les corrections appliquées.';
      recent.appendChild(hint);
    }
    rows.slice(0, 8).forEach(function (e, i) {
      var row = document.createElement('div');
      row.className = 'rank-row';

      var pos = document.createElement('span');
      pos.className = 'rank-pos';
      pos.textContent = (i + 1);
      var kind = document.createElement('span');
      kind.className = 'chip chip-kind kind-' + e.kind;
      kind.textContent = (Records.KINDS[e.kind] || {}).short || 'LOT';
      var label = document.createElement('span');
      label.className = 'rank-label';
      label.textContent = e.label;
      var meta = document.createElement('span');
      meta.className = 'rank-meta';
      meta.textContent = e.files + ' f · ' + e.sources + ' src · ' + recordDate(e.ts);
      var pts = document.createElement('span');
      pts.className = 'rank-score';
      pts.textContent = recordFloat(e.score);

      row.appendChild(pos);
      row.appendChild(kind);
      row.appendChild(label);
      row.appendChild(meta);
      row.appendChild(pts);
      recent.appendChild(row);
    });
  }

  if (window.Records) {
    Records.onChange = renderRecords;
    renderRecords();
    var recClear = $('rec-clear');
    if (recClear) {
      recClear.addEventListener('click', function () {
        if (window.confirm('Vider le classement enregistré dans ce navigateur ?')) Records.clear();
      });
    }
  }

  /* ------------------------------------------------------------------ *
   * Comptes locaux : connexion, inscription, code de récupération.
   * ------------------------------------------------------------------ */
  (function () {
    if (!window.Accounts) return;
    var overlay = $('auth-overlay');
    var msg = $('auth-msg');
    var codeBox = $('auth-code');
    if (!overlay) return;

    function show(view) {
      ['login', 'signup', 'recover', 'me'].forEach(function (v) {
        var el = $('auth-' + v);
        if (el) el.hidden = v !== view;
      });
      var meMode = view === 'me' || view === 'fb';
      $('auth-tabs').hidden = meMode;
      $('auth-providers').hidden = meMode;
      $('auth-sep').hidden = meMode;
      Array.prototype.forEach.call(overlay.querySelectorAll('.auth-tab'), function (b) {
        var on = b.dataset.go === view;
        b.classList.toggle('is-active', on);
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      if (view !== 'me') codeBox.hidden = true;
      msg.hidden = true;
    }

    function say(text, bad) {
      msg.hidden = false;
      msg.textContent = text;
      msg.className = 'auth-msg ' + (bad ? 'is-bad' : 'is-ok');
    }

    function showCode(code) {
      $('auth-code-value').textContent = code;
      codeBox.hidden = false;
    }

    function renderMe(me) {
      var label = me.name || me.email;
      $('me-name').textContent = label;
      $('me-mail').textContent = me.email;
      $('me-since').textContent = 'Compte local créé le ' + new Date(me.createdAt).toLocaleDateString('fr-FR');
      $('me-avatar').textContent = label.charAt(0).toUpperCase();
    }

    var fbUser = null;
    var fbOnline = false;

    function displayName(user) {
      return user.name || user.email || 'Compte Freebuff';
    }

    function fillFb() {
      var label = displayName(fbUser);
      $('fb-name').textContent = label;
      $('fb-mail').textContent = fbUser.email || 'Profil sans e-mail partagé';
      $('fb-avatar').textContent = label.charAt(0).toUpperCase();
    }

    function renderHeader() {
      var me = Accounts.current();
      var label = fbUser ? displayName(fbUser) : me ? (me.name || me.email) : 'Se connecter';
      $('account-label').textContent = label;
      $('account-avatar').textContent = (fbUser || me) ? label.charAt(0).toUpperCase() : '?';
      $('account-open').classList.toggle('is-in', !!(fbUser || me));
    }

    function open() {
      overlay.hidden = false;
      var me = Accounts.current();
      if (fbUser) { fillFb(); show('fb'); } else if (me) { renderMe(me); show('me'); } else { show('login'); }
    }

    function close() { overlay.hidden = true; }

    $('account-open').addEventListener('click', open);
    $('auth-close').addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !overlay.hidden) close();
    });

    Array.prototype.forEach.call(overlay.querySelectorAll('[data-go]'), function (b) {
      b.addEventListener('click', function () { show(b.dataset.go); });
    });

    /* Connexion GitHub par Device Flow : aucun serveur ni secret requis.
       L'app demande un code, l'utilisateur le valide sur github.com/login/device,
       on interroge le jeton puis le profil. Client ID public de l'OAuth app. */
    var GITHUB_CLIENT_ID = 'Ov23liZtDYCCxZcQSMfB';
    function githubDeviceLogin() {
      var httpFetch = window.cypherFetch || fetch;
      say('Demande du code de connexion GitHub…');
      httpFetch('https://github.com/login/device/code', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, scope: 'read:user' })
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (!d.device_code) throw new Error(d.error_description || 'device-refused');
        say('Code : ' + d.user_code + ' — la page GitHub s’ouvre, validez-le.');
        var url = d.verification_uri || 'https://github.com/login/device';
        try {
          if (window.__TAURI__ && window.__TAURI__.shell && window.__TAURI__.shell.open) {
            window.__TAURI__.shell.open(url + '?user_code=' + encodeURIComponent(d.user_code));
          } else window.open(url, '_blank');
        } catch (e) { window.open(url, '_blank'); }
        var wait = (d.interval || 5) * 1000, deadline = Date.now() + (d.expires_in || 900) * 1000;
        (function poll() {
          if (Date.now() > deadline) return say('Code expiré : recommencez la connexion GitHub.', true);
          httpFetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, device_code: d.device_code, grant_type: 'urn:ietf:params:oauth:grant-type:device_code' })
          }).then(function (r) { return r.json(); }).then(function (t) {
            if (t.error === 'authorization_pending') return setTimeout(poll, wait);
            if (t.error === 'slow_down') { wait += 5000; return setTimeout(poll, wait); }
            if (t.error) return say('GitHub : ' + (t.error_description || t.error), true);
            httpFetch('https://api.github.com/user', { headers: { authorization: 'Bearer ' + t.access_token, accept: 'application/json' } })
              .then(function (r) { return r.json(); }).then(function (u) {
                fbUser = { name: u.name || u.login, email: u.email || (u.login + '@github'), provider: 'github', avatar: u.avatar_url };
                renderHeader(); renderMe(fbUser); show('me');
              });
          }).catch(function () { say('Réseau : impossible de joindre GitHub.', true); });
        })();
      }).catch(function (e) { say('GitHub indisponible : ' + e.message, true); });
    }

    Array.prototype.forEach.call(overlay.querySelectorAll('[data-provider]'), function (b) {
      b.addEventListener('click', function () {
        var name = b.dataset.provider;
        if (name === 'GitHub') { githubDeviceLogin(); return; }
        if (name === 'Microsoft') {
          say('Freebuff fédère Google, GitHub et Apple — pas Microsoft. Utilisez Freebuff, Google, GitHub ou l’adresse e-mail ci-dessous.', true);
          return;
        }
        if (!fbOnline) {
          say('La connexion ' + name + ' est servie par la version hébergée du site : ce serveur local n’expose pas /auth/freebuff.', true);
          return;
        }
        window.location.href = '/auth/freebuff/signin?returnTo=' +
          encodeURIComponent(location.pathname + location.search);
      });
    });

    /* Session Freebuff éventuelle : lue au chargement, jamais de jeton côté page. */
    fetch('/auth/freebuff/session', { credentials: 'same-origin', headers: { accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('auth-off'); return r.json(); })
      .then(function (d) {
        fbOnline = true;
        fbUser = d && d.user ? d.user : null;
        renderHeader();
      })
      .catch(function () { fbOnline = false; renderHeader(); });

    if (!Accounts.available) {
      say('Stockage local ou chiffrement indisponible : ouvrez le site en HTTPS ou sur localhost.', true);
    }

    $('auth-login').addEventListener('submit', function (e) {
      e.preventDefault();
      Accounts.signIn({ email: $('login-email').value, password: $('login-password').value }).then(function (r) {
        if (!r.ok) return say(r.error, true);
        $('login-password').value = '';
        renderMe(r.user);
        show('me');
        say('Connecté en tant que ' + r.user.email, false);
      });
    });

    $('auth-signup').addEventListener('submit', function (e) {
      e.preventDefault();
      Accounts.signUp({
        name: $('signup-name').value,
        email: $('signup-email').value,
        password: $('signup-password').value
      }).then(function (r) {
        if (!r.ok) return say(r.error, true);
        $('signup-password').value = '';
        renderMe(r.user);
        show('me');
        say('Compte créé. Conservez le code de récupération ci-dessous.', false);
        showCode(r.recoveryCode);
      });
    });

    $('auth-recover').addEventListener('submit', function (e) {
      e.preventDefault();
      Accounts.recover({
        email: $('recover-email').value,
        code: $('recover-code').value,
        password: $('recover-password').value
      }).then(function (r) {
        if (!r.ok) return say(r.error, true);
        $('recover-password').value = '';
        $('recover-code').value = '';
        renderMe(r.user);
        show('me');
        say('Mot de passe réinitialisé. Un nouveau code de récupération a été généré.', false);
        showCode(r.recoveryCode);
      });
    });

    $('auth-pass').addEventListener('submit', function (e) {
      e.preventDefault();
      Accounts.changePassword({ current: $('pass-current').value, next: $('pass-next').value }).then(function (r) {
        if (!r.ok) return say(r.error, true);
        $('pass-current').value = '';
        $('pass-next').value = '';
        say('Mot de passe changé.', false);
      });
    });

    $('me-recovery').addEventListener('click', function () {
      Accounts.resetRecovery().then(function (r) {
        if (!r.ok) return say(r.error, true);
        say('Nouveau code de récupération généré : l’ancien ne fonctionne plus.', false);
        showCode(r.recoveryCode);
      });
    });

    $('me-logout').addEventListener('click', function () {
      Accounts.signOut();
      show('login');
      say('Déconnecté.', false);
    });

    $('auth-code-copy').addEventListener('click', function () {
      copyText($('auth-code-value').textContent, $('auth-code-copy'));
    });

    Accounts.onChange = function () {
      renderHeader();
      var me = Accounts.current();
      if (fbUser) { fillFb(); show('fb'); } else if (me) { renderMe(me); show('me'); } else { show('login'); }
    };
    renderHeader();
  })();

  /* ------------------------------ source obfusquée ------------------------------ */
  $('file-source').addEventListener('change', function (e) {
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    readText(f).then(function (t) { $('src-input').value = t; });
  });

  $('src-run').addEventListener('click', function () {
    var text = $('src-input').value;
    if (!text.trim()) {
      $('src-output').textContent = '—';
      $('src-log').textContent = '';
      $('src-copy').disabled = true;
      return;
    }
    var res = Deobf.deobfuscate(text);
    $('src-output').textContent = res.code;
    $('src-copy').disabled = false;
    var log = $('src-log');
    log.textContent = '';
    res.log.forEach(function (entry) {
      var li = document.createElement('li');
      var b = document.createElement('b');
      b.textContent = entry.pass;
      li.appendChild(b);
      li.appendChild(document.createTextNode(' — ' + entry.detail));
      log.appendChild(li);
    });
  });

  $('src-copy').addEventListener('click', function () {
    copyText($('src-output').textContent, $('src-copy'));
  });

  /* ------------------------------------------------------------------ *
   * AntiBackdoor : audit statique d'un dépôt (fichiers, dossier, zip).
   * ------------------------------------------------------------------ */
  var SCAN_EXT = { '.lua': 'lua', '.js': 'js', '.mjs': 'js', '.html': 'html', '.htm': 'html', '.css': 'css' };

  function kindOfPath(path) {
    var m = /\.[A-Za-z0-9]+$/.exec(String(path));
    return m ? (SCAN_EXT[m[0].toLowerCase()] || null) : null;
  }

  function fillStats(dl, pairs) {
    dl.textContent = '';
    dl.hidden = false;
    pairs.forEach(function (c) {
      var d = document.createElement('div');
      var dt = document.createElement('dt');
      dt.textContent = c[0];
      var dd = document.createElement('dd');
      dd.textContent = c[1];
      d.appendChild(dt);
      d.appendChild(dd);
      dl.appendChild(d);
    });
  }

  function fillLog(ol, entries) {
    ol.textContent = '';
    entries.forEach(function (entry) {
      var li = document.createElement('li');
      var b = document.createElement('b');
      b.textContent = entry.pass;
      li.appendChild(b);
      li.appendChild(document.createTextNode(' — ' + entry.detail));
      ol.appendChild(li);
    });
  }

  function fillNotes(ul, warnings) {
    ul.textContent = '';
    ul.hidden = !warnings.length;
    warnings.forEach(function (w) {
      var li = document.createElement('li');
      li.className = 'warn';
      li.textContent = w;
      ul.appendChild(li);
    });
  }

  function renderFindings(findings, host) {
    var box = document.createElement('div');
    box.className = 'findings';
    findings.forEach(function (f) {
      var row = document.createElement('div');
      row.className = 'finding';
      var sev = document.createElement('span');
      sev.className = 'sev sev-' + f.severity;
      sev.textContent = f.severity;
      var body = document.createElement('div');
      var title = document.createElement('div');
      title.className = 'finding-title';
      title.textContent = f.title;
      var meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = 'ligne ' + f.line + ' · ' + f.why;
      body.appendChild(title);
      body.appendChild(meta);
      if (f.snippet) {
        var sn = document.createElement('code');
        sn.className = 'snip';
        sn.textContent = f.snippet;
        body.appendChild(sn);
      }
      if (f.advice) {
        var adv = document.createElement('div');
        adv.className = 'meta';
        adv.textContent = '→ ' + f.advice;
        body.appendChild(adv);
      }
      row.appendChild(sev);
      row.appendChild(body);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function backdoorCard(report) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = report.name;
    var right = document.createElement('span');
    right.className = 'filebadge';
    var parts = [];
    ['critical', 'high', 'medium', 'low'].forEach(function (k) {
      if (report.counts[k]) parts.push(report.counts[k] + ' ' + k);
    });
    right.textContent = parts.join(' · ') + ' · ' + report.lines + ' ligne(s)';
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (!det.open || det.dataset.built) return;
      det.dataset.built = '1';
      renderFindings(report.findings, body);
      if (report.text) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-ghost';
        btn.textContent = 'Nettoyer les noms L_xx';
        var out = document.createElement('pre');
        out.className = 'code code-box';
        out.hidden = true;
        btn.addEventListener('click', function () {
          var res = Anti.cleanLua(report.text);
          out.textContent = res.code;
          out.hidden = false;
          var dl = document.createElement('button');
          dl.type = 'button';
          dl.className = 'btn btn-primary';
          dl.style.marginLeft = '8px';
          dl.textContent = 'Télécharger .lua';
          dl.addEventListener('click', function () {
            download(srcBaseName(report.name) + '.clean.lua', res.code);
          });
          body.appendChild(dl);
        });
        body.appendChild(btn);
        body.appendChild(out);
      }
    });
    det.appendChild(body);
    return det;
  }

  function renderBackdoor(results, meta) {
    var host = $('backdoor-result');
    host.textContent = '';
    host.hidden = false;

    var totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    results.forEach(function (r) {
      Object.keys(totals).forEach(function (k) { totals[k] += r.counts[k] || 0; });
    });
    var flagged = results.filter(function (r) { return r.findings.length; });

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (totals.critical ? 'is-fxap' : totals.high ? 'is-warn' : 'is-ok');
    badge.textContent = totals.critical
      ? totals.critical + ' constat(s) critique(s)'
      : totals.high ? totals.high + ' constat(s) élevé(s)'
        : flagged.length ? flagged.length + ' fichier(s) à vérifier' : 'aucun constat';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.scanned + ' fichier(s) audité(s) · ' + flagged.length + ' avec constat(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s) (binaire, extension ou taille)' : '');
    head.appendChild(badge);
    head.appendChild(sub);
    host.appendChild(head);

    if (!flagged.length) {
      var ok = document.createElement('p');
      ok.className = 'limit';
      ok.textContent = 'Aucun motif d’exécution système, de sortie réseau, de chargement dynamique, de hook debug ou d’obfuscation détecté. Ce n’est pas une preuve d’innocuité : un code chiffré, ou une logique malveillante sans motif connu, passe sous un filtre statique.';
      host.appendChild(ok);
      return;
    }

    var list = document.createElement('div');
    list.className = 'filelist';
    flagged.forEach(function (r) { list.appendChild(backdoorCard(r)); });
    host.appendChild(list);
  }

  async function handleBackdoorScan(payload) {
    var host = $('backdoor-result');
    var prog = $('backdoor-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var results = [];
    var scanned = 0;
    var skipped = 0;

    while (queue.length && scanned < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      var kind = kindOfPath(item.path);
      if (!kind || bytes.length > MAX_FILE_BYTES || bytes.subarray(0, 4096).indexOf(0) !== -1) {
        skipped++;
        bytes = null;
        continue;
      }

      prog.textContent = 'Audit ' + (scanned + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var text = new TextDecoder('utf-8').decode(bytes);
      bytes = null;
      var report = kind === 'lua' ? Anti.scanLua(text, item.path) : Nui.scan(text, kind, item.path);
      report.text = (kind === 'lua' && report.artifacts > 0 && text.length <= 1500000) ? text : null;
      results.push(report);
      scanned++;
    }

    prog.hidden = true;
    renderBackdoor(results, { scanned: scanned, skipped: skipped });

    if (window.Records) {
      var bdFindings = results.reduce(function (n, r) {
        return n + (r.findings && r.findings.length ? r.findings.length : 0);
      }, 0);
      Records.add({
        kind: 'backdoor',
        label: 'AntiCleanBackdoor',
        files: scanned,
        sources: 0,
        findings: bdFindings
      });
    }
  }

  var dzBd = $('dz-backdoor');
  ['dragenter', 'dragover'].forEach(function (ev) {
    dzBd.addEventListener(ev, function (e) { e.preventDefault(); dzBd.classList.add('is-drag'); });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    dzBd.addEventListener(ev, function (e) { e.preventDefault(); dzBd.classList.remove('is-drag'); });
  });
  dzBd.addEventListener('drop', function (e) {
    e.preventDefault();
    dzBd.classList.remove('is-drag');
    handleBackdoorScan(collectDropped(e.dataTransfer));
  });

  ['file-backdoor', 'dir-backdoor'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleBackdoorScan({ entries: null, files: files });
      e.target.value = '';
    });
  });

  /* ------------------------------------------------------------------ *
   * AntiCleanLUA : nettoyage par lot (fichiers, dossier, archive .zip).
   * ------------------------------------------------------------------ */
  function luaCard(result) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = result.path;
    var right = document.createElement('span');
    right.className = 'filebadge';
    right.textContent = result.res.stats.renames + ' renommage(s) · ' +
      result.res.stats.removedLines + ' ligne(s) retirée(s) · ' + fmtBytes(result.res.stats.afterBytes);
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (!det.open || det.dataset.built) return;
      det.dataset.built = '1';

      var pre = document.createElement('pre');
      pre.className = 'code code-box';
      pre.hidden = true;
      pre.textContent = stampLua(result.res, result.path);

      if (result.res.log.length) {
        var log = document.createElement('ol');
        log.className = 'passes';
        result.res.log.forEach(function (entry) {
          var li = document.createElement('li');
          var b = document.createElement('b');
          b.textContent = entry.pass;
          li.appendChild(b);
          li.appendChild(document.createTextNode(' — ' + entry.detail));
          log.appendChild(li);
        });
        body.appendChild(log);
      }

      if (result.res.warnings.length) {
        var notes = document.createElement('ul');
        notes.className = 'notes';
        result.res.warnings.forEach(function (w) {
          var li = document.createElement('li');
          li.className = 'warn';
          li.textContent = w;
          notes.appendChild(li);
        });
        body.appendChild(notes);
      }

      var actions = document.createElement('div');
      actions.className = 'result-actions';
      actions.style.margin = '14px 0 10px';
      var view = document.createElement('button');
      view.type = 'button';
      view.className = 'btn btn-ghost';
      view.textContent = 'Voir le code nettoyé';
      var dl = document.createElement('button');
      dl.type = 'button';
      dl.className = 'btn btn-primary';
      dl.textContent = 'Télécharger';
      view.addEventListener('click', function () {
        pre.hidden = !pre.hidden;
        view.textContent = pre.hidden ? 'Voir le code nettoyé' : 'Masquer le code nettoyé';
      });
      dl.addEventListener('click', function () {
        var base = srcBaseName(String(result.path).split(' › ').pop());
        download(base + '.clean.lua', stampLua(result.res, result.path));
      });
      actions.appendChild(view);
      actions.appendChild(dl);
      body.appendChild(actions);
      body.appendChild(pre);
    });

    det.appendChild(body);
    return det;
  }

  function renderLua(results, meta) {
    var host = $('cleanlua-result');
    host.textContent = '';
    host.hidden = false;

    var renames = results.reduce(function (n, r) { return n + r.res.stats.renames; }, 0);
    var removed = results.reduce(function (n, r) { return n + r.res.stats.removedLines; }, 0);

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict is-ok';
    badge.textContent = results.length + ' fichier(s) nettoyé(s)';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = renames + ' renommage(s) · ' + removed + ' ligne(s) retirée(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s)' : '');
    var exportBtn = document.createElement('button');
    exportBtn.type = 'button';
    exportBtn.className = 'btn btn-primary';
    exportBtn.textContent = 'Télécharger le lot nettoyé (.zip)';
    exportBtn.addEventListener('click', function () { exportLuaZip(results); });
    head.appendChild(badge);
    head.appendChild(sub);
    head.appendChild(exportBtn);
    host.appendChild(head);

    var list = document.createElement('div');
    list.className = 'filelist';
    results.forEach(function (r) { list.appendChild(luaCard(r)); });
    host.appendChild(list);
  }

  async function handleLuaBatch(payload) {
    var host = $('cleanlua-result');
    var prog = $('cleanlua-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var results = [];
    var done = 0;
    var skipped = 0;

    while (queue.length && done < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      if (bytes.length > MAX_FILE_BYTES || bytes.subarray(0, 4096).indexOf(0) !== -1) {
        skipped++;
        bytes = null;
        continue;
      }

      prog.textContent = 'Nettoyage ' + (done + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var text = new TextDecoder('utf-8').decode(bytes);
      bytes = null;
      if (!text.trim()) { skipped++; continue; }

      results.push({ path: item.path, res: Anti.cleanLua(text) });
      done++;
    }

    prog.hidden = true;
    renderLua(results, { files: done, skipped: skipped });
  }

  var dzLua = $('dz-cleanlua');
  ['dragenter', 'dragover'].forEach(function (ev) {
    dzLua.addEventListener(ev, function (e) { e.preventDefault(); dzLua.classList.add('is-drag'); });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    dzLua.addEventListener(ev, function (e) { e.preventDefault(); dzLua.classList.remove('is-drag'); });
  });
  dzLua.addEventListener('drop', function (e) {
    e.preventDefault();
    dzLua.classList.remove('is-drag');
    handleLuaBatch(collectDropped(e.dataTransfer));
  });

  ['file-cleanlua', 'dir-cleanlua'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleLuaBatch({ entries: null, files: files });
      e.target.value = '';
    });
  });

  /* Archive marquée CypherDecrypter : un clic, un .zip prêt à remplacer l'original. */
  function downloadZip(files, archiveName) {
    var bytes = Zip.create(files, { comment: 'Nettoyé par CypherDecrypter' });
    var blob = new Blob([bytes], { type: 'application/zip' });
    if (window.CypherBridge && window.CypherBridge.save) { window.CypherBridge.save(archiveName, blob); return; }
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = archiveName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
  }

  function stampLua(res, path) {
    var when = new Date().toLocaleString('fr-FR');
    var line = 'Nettoyé par CypherDecrypter · AntiCleanLUA · ' + when +
      ' · ' + res.stats.renames + ' renommage(s), ' + res.stats.removedLines + ' ligne(s) retirée(s)';
    var note = 'Fichier généré : relisez-le avant de remplacer l’original.';
    var ext = (/\.([a-z0-9]+)$/i.exec(String(path || (res && res.path) || '')) || [])[1];
    ext = (ext || 'lua').toLowerCase();
    if (ext === 'js' || ext === 'mjs' || ext === 'cjs' || ext === 'ts') {
      return '// ' + line + '\n// ' + note + '\n\n' + res.code;
    }
    if (ext === 'css' || ext === 'scss' || ext === 'less') {
      return '/* ' + line + ' */\n/* ' + note + ' */\n\n' + res.code;
    }
    if (ext === 'html' || ext === 'htm') {
      var header = '<!-- ' + line + ' — ' + note + ' -->\n';
      var doctype = /^\s*<!doctype[^>]*>\s*/i.exec(res.code);
      if (doctype) return doctype[0].replace(/\s+$/, '') + '\n' + header + res.code.slice(doctype[0].length);
      return header + res.code;
    }
    if (ext !== 'lua') return res.code; // json, md, ymap… : aucun tampon, la syntaxe casserait
    return '-- ' + line + '\n-- ' + note + '\n\n' + res.code;
  }

  function exportLuaZip(results) {
    if (!results || !results.length) return;
    var when = new Date().toLocaleString('fr-FR');
    var used = Object.create(null);
    var files = [];
    var lines = [
      'CypherDecrypter — AntiCleanLUA',
      'Archive générée le ' + when,
      '',
      results.length + ' fichier(s) nettoyé(s) :'
    ];

    results.forEach(function (r) {
      var path = String(r.path).split(' › ').pop();
      if (used[path]) {
        var ext = /\.[A-Za-z0-9]+$/.exec(path);
        path = ext
          ? path.slice(0, -ext[0].length) + '-' + used[path] + ext[0]
          : path + '-' + used[path];
      }
      used[path] = (used[path] || 1) + 1;
      files.push({ path: path, text: stampLua(r.res, r.path) });
      lines.push('- ' + path + '  ' + r.res.stats.renames + ' renommage(s), ' +
        r.res.stats.removedLines + ' ligne(s) retirée(s), ' +
        fmtBytes(r.res.stats.beforeBytes) + ' → ' + fmtBytes(r.res.stats.afterBytes));
    });

    lines.push('', 'Code nettoyé et réindenté ; relisez-le avant de remplacer l’original.', 'Marked by CypherDecrypter.');
    files.push({ path: 'CYPHERDECRYPTER.txt', text: lines.join('\n') + '\n' });

    if (window.Records) {
      var recFix = 0;
      results.forEach(function (r) { recFix += r.res.stats.renames + r.res.stats.removedLines; });
      Records.add({
        kind: 'lua',
        label: 'AntiCleanLUA',
        files: results.length,
        sources: results.length,
        findings: recFix
      });
    }

    downloadZip(files, 'CypherDecrypter-clean-' + stampDate() + '.zip');
  }

  /* ------------------------------------------------------------------ *
   * AntiCleanNUI : audit + nettoyage d'un lot NUI (fichiers, dossier, zip).
   * ------------------------------------------------------------------ */
  function nuiCard(result) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = result.path;
    var right = document.createElement('span');
    right.className = 'filebadge';
    right.textContent = result.kind.toUpperCase() +
      (result.report.verdict ? ' · ' + result.report.verdict : '') +
      (result.res && result.res.stats && result.res.stats.renames ? ' · ' + result.res.stats.renames + ' renommage(s)' : '') +
      (result.res && result.res.stats && result.res.stats.removedLines ? ' · ' + result.res.stats.removedLines + ' ligne(s) retirée(s)' : '') +
      ' · ' + result.report.findings.length + ' constat(s)';
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (!det.open || det.dataset.built) return;
      det.dataset.built = '1';

      if (result.report.findings.length) {
        renderFindings(result.report.findings, body);
      } else {
        var ok = document.createElement('p');
        ok.className = 'limit';
        ok.textContent = 'Aucun motif suspect connu dans ce fichier.';
        body.appendChild(ok);
      }

      if (result.res.warnings.length) {
        var notes = document.createElement('ul');
        notes.className = 'notes';
        result.res.warnings.forEach(function (w) {
          var li = document.createElement('li');
          li.className = 'warn';
          li.textContent = w;
          notes.appendChild(li);
        });
        body.appendChild(notes);
      }

      var actions = document.createElement('div');
      actions.className = 'result-actions';
      actions.style.margin = '14px 0 10px';
      var view = document.createElement('button');
      view.type = 'button';
      view.className = 'btn btn-ghost';
      view.textContent = 'Voir le code nettoyé';
      var dl = document.createElement('button');
      dl.type = 'button';
      dl.className = 'btn btn-primary';
      dl.textContent = 'Télécharger';
      var pre = document.createElement('pre');
      pre.className = 'code code-box';
      pre.hidden = true;
      pre.textContent = result.res.code;
      view.addEventListener('click', function () {
        pre.hidden = !pre.hidden;
        view.textContent = pre.hidden ? 'Voir le code nettoyé' : 'Masquer le code nettoyé';
      });
      dl.addEventListener('click', function () {
        var full = String(result.path).split(' › ').pop();
        var base = srcBaseName(full);
        download(result.kind === 'lua' ? full : base + '.clean.' + result.kind, result.res.code);
      });
      actions.appendChild(view);
      actions.appendChild(dl);
      body.appendChild(actions);
      body.appendChild(pre);
    });

    det.appendChild(body);
    return det;
  }

  /* Tout le lot nettoyé en un clic : un seul .zip, arborescence d'origine conservée. */
  function exportNuiZip(results) {
    if (!results || !results.length) return;
    var used = Object.create(null);
    var files = [];
    var lines = [
      'CypherDecrypter — AntiCleanNUI & LUA',
      'Archive générée le ' + new Date().toLocaleString('fr-FR'),
      '',
      results.length + ' fichier(s) nettoyé(s) :'
    ];

    results.forEach(function (r) {
      var path = String(r.path).replace(/ › /g, '/');
      if (used[path]) {
        var ext = /\.[A-Za-z0-9]+$/.exec(path);
        path = ext
          ? path.slice(0, -ext[0].length) + '-' + used[path] + ext[0]
          : path + '-' + used[path];
      }
      used[path] = (used[path] || 1) + 1;
      files.push({ path: path, text: r.res.code });
      lines.push('- ' + path + '  ' + r.report.findings.length + ' constat(s) · ' + (r.kind || 'lua'));
    });

    lines.push('', 'Code nettoyé, prêt à remplacer l’original. Marked by CypherDecrypter.');
    files.push({ path: 'CYPHERDECRYPTER.txt', text: lines.join('\n') + '\n' });
    downloadZip(files, 'CypherDecrypter-clean-nui-' + stampDate() + '.zip');
  }

  function renderNui(results, meta) {
    var host = $('cleannui-result');
    host.textContent = '';
    host.hidden = false;

    var crit = results.reduce(function (n, r) { return n + r.report.counts.critical; }, 0);
    var high = results.reduce(function (n, r) { return n + r.report.counts.high; }, 0);
    var found = results.reduce(function (n, r) { return n + r.report.findings.length; }, 0);

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (crit ? 'is-fxap' : high ? 'is-warn' : 'is-ok');
    badge.textContent = found ? found + ' constat(s)' : 'aucun constat';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.files + ' fichier(s) traité(s) · ' + crit + ' critique(s) et ' + high + ' élevé(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s)' : '');
    var all = document.createElement('button');
    all.type = 'button';
    all.className = 'btn btn-ok';
    all.id = 'cleannui-zip';
    all.textContent = 'Tout télécharger (.zip)';
    all.disabled = !results.length;
    all.title = 'Tous les fichiers nettoyés de ce lot dans une seule archive, arborescence conservée';
    all.addEventListener('click', function () { exportNuiZip(results); });
    head.appendChild(badge);
    head.appendChild(sub);
    head.appendChild(all);
    host.appendChild(head);

    var list = document.createElement('div');
    list.className = 'filelist';
    results.forEach(function (r) { list.appendChild(nuiCard(r)); });
    host.appendChild(list);
  }

  async function handleNuiBatch(payload) {
    var host = $('cleannui-result');
    var prog = $('cleannui-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var results = [];
    var done = 0;
    var skipped = 0;

    while (queue.length && done < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      var kind = Nui.kindOf(item.path);
      if (!kind && /\.lua$/i.test(item.path)) kind = 'lua';
      if (!kind || bytes.length > MAX_FILE_BYTES || bytes.subarray(0, 4096).indexOf(0) !== -1) {
        skipped++;
        bytes = null;
        continue;
      }

      prog.textContent = 'Analyse ' + (done + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var text = new TextDecoder('utf-8').decode(bytes);
      bytes = null;
      if (!text.trim()) { skipped++; continue; }

      if (kind === 'lua') {
        results.push({
          path: item.path,
          kind: 'lua',
          report: Anti.scanLua(text, item.path),
          res: Anti.cleanLua(text)
        });
      } else {
        results.push({
          path: item.path,
          kind: kind,
          report: Nui.scan(text, kind, item.path),
          res: Nui.clean(text, kind)
        });
      }
      done++;
    }

    prog.hidden = true;
    renderNui(results, { files: done, skipped: skipped });

    if (window.Records) {
      var nuiFindings = results.reduce(function (n, r) { return n + r.report.findings.length; }, 0);
      Records.add({
        kind: 'nui',
        label: 'AntiCleanNUI & LUA',
        files: done,
        sources: done,
        findings: nuiFindings
      });
    }
  }

  var dzNui = $('dz-cleannui');
  ['dragenter', 'dragover'].forEach(function (ev) {
    dzNui.addEventListener(ev, function (e) { e.preventDefault(); dzNui.classList.add('is-drag'); });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    dzNui.addEventListener(ev, function (e) { e.preventDefault(); dzNui.classList.remove('is-drag'); });
  });
  dzNui.addEventListener('drop', function (e) {
    e.preventDefault();
    dzNui.classList.remove('is-drag');
    handleNuiBatch(collectDropped(e.dataTransfer));
  });

  ['file-cleannui', 'dir-cleannui'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleNuiBatch({ entries: null, files: files });
      e.target.value = '';
    });
  });

  /* ------------------------------------------------------------------ *
   * AntiCleanBackdoor : dépouillage par lot (fichiers, dossier, archive).
   * ------------------------------------------------------------------ */
  var sanitizeResults = [];

  function stampDate() {
    var d = new Date();
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + '_' +
      p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  /* En-tête de génération : marque le fichier comme nettoyé par CypherDecrypter. */
  function stampClean(result) {
    var when = new Date().toLocaleString('fr-FR');
    var line = 'Nettoyé par CypherDecrypter · AntiCleanBackdoor · ' + when +
      ' · ' + result.removed.length + ' neutralisation(s)';
    var note = 'Fichier généré : les lignes désarmées restent visibles en commentaire [retiré: …].';
    if (result.kind === 'lua') return '-- ' + line + '\n-- ' + note + '\n\n' + result.code;
    if (result.kind === 'js') return '// ' + line + '\n// ' + note + '\n\n' + result.code;
    if (result.kind === 'css') return '/* ' + line + ' */\n/* ' + note + ' */\n\n' + result.code;
    if (result.kind === 'html') {
      var header = '<!-- ' + line + ' — ' + note + ' -->\n';
      var doctype = /^\s*<!doctype[^>]*>\s*/i.exec(result.code);
      if (doctype) return doctype[0].replace(/\s+$/, '') + '\n' + header + result.code.slice(doctype[0].length);
      return header + result.code;
    }
    return result.code;
  }

  function exportSanitizeZip(results) {
    if (!results || !results.length) return;
    var when = new Date().toLocaleString('fr-FR');
    var used = Object.create(null);
    var files = [];
    var lines = [
      'CypherDecrypter — AntiCleanBackdoor',
      'Archive générée le ' + when,
      '',
      results.length + ' fichier(s) nettoyé(s) :'
    ];

    results.forEach(function (r) {
      var path = String(r.path).split(' › ').pop();
      if (used[path]) {
        var ext = /\.[A-Za-z0-9]+$/.exec(path);
        path = ext
          ? path.slice(0, -ext[0].length) + '-' + used[path] + ext[0]
          : path + '-' + used[path];
      }
      used[path] = (used[path] || 1) + 1;
      files.push({ path: path, text: stampClean(r) });
      lines.push('- ' + path + '  [' + r.kind + ']  ' + r.removed.length + ' neutralisé(s), ' +
        r.after.critical + ' critique(s) restant(s), ' + r.stats.beforeBytes + ' → ' + r.stats.afterBytes + ' octets');
    });

    lines.push('',
      'Chaque motif désarmé est conservé en commentaire sur la ligne concernée.',
      'Filtre statique : il ne garantit pas l’absence de backdoor. Testez la ressource après remplacement.',
      'Marked by CypherDecrypter.');
    files.push({ path: 'CYPHERDECRYPTER.txt', text: lines.join('\n') + '\n' });

    var bytes = Zip.create(files, { comment: 'Nettoyé par CypherDecrypter' });
    var blob = new Blob([bytes], { type: 'application/zip' });
    var outName = 'CypherDecrypter-clean-' + stampDate() + '.zip';
    if (window.CypherBridge && window.CypherBridge.save) { window.CypherBridge.save(outName, blob); return; }
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = outName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
  }

  function sanitizeCard(result) {
    var det = document.createElement('details');
    det.className = 'filecard';

    var sum = document.createElement('summary');
    var left = document.createElement('span');
    left.className = 'fname';
    left.textContent = result.path;
    var right = document.createElement('span');
    right.className = 'filebadge';
    right.textContent = result.kind.toUpperCase() + ' · ' + result.removed.length + ' neutralisé(s) · ' +
      result.after.critical + ' critique(s) restant(s)';
    sum.appendChild(left);
    sum.appendChild(right);
    det.appendChild(sum);

    var body = document.createElement('div');
    body.className = 'filebody';
    det.addEventListener('toggle', function () {
      if (!det.open || det.dataset.built) return;
      det.dataset.built = '1';

      if (result.removed.length) {
        var box = document.createElement('div');
        box.className = 'findings';
        result.removed.forEach(function (item) {
          var row = document.createElement('div');
          row.className = 'finding';
          var sev = document.createElement('span');
          sev.className = 'sev sev-low';
          sev.textContent = 'retiré';
          var cell = document.createElement('div');
          var title = document.createElement('div');
          title.className = 'finding-title';
          title.textContent = item.title;
          var meta = document.createElement('div');
          meta.className = 'meta';
          meta.textContent = 'ligne ' + item.line + ' · commenté dans le fichier produit';
          var sn = document.createElement('code');
          sn.className = 'snip';
          sn.textContent = item.snippet.slice(0, 160);
          cell.appendChild(title);
          cell.appendChild(meta);
          cell.appendChild(sn);
          row.appendChild(sev);
          row.appendChild(cell);
          box.appendChild(row);
        });
        body.appendChild(box);
      } else {
        var ok = document.createElement('p');
        ok.className = 'limit';
        ok.textContent = 'Aucun motif dangereux connu dans ce fichier : seul le formatage a été nettoyé.';
        body.appendChild(ok);
      }

      if (result.warnings.length) {
        var notes = document.createElement('ul');
        notes.className = 'notes';
        result.warnings.forEach(function (w) {
          var li = document.createElement('li');
          li.className = 'warn';
          li.textContent = w;
          notes.appendChild(li);
        });
        body.appendChild(notes);
      }

      var actions = document.createElement('div');
      actions.className = 'result-actions';
      actions.style.margin = '14px 0 10px';
      var view = document.createElement('button');
      view.type = 'button';
      view.className = 'btn btn-ghost';
      view.textContent = 'Voir le code assaini';
      var dl = document.createElement('button');
      dl.type = 'button';
      dl.className = 'btn btn-primary';
      dl.textContent = 'Télécharger';
      var stamped = stampClean(result);
      var pre = document.createElement('pre');
      pre.className = 'code code-box';
      pre.hidden = true;
      pre.textContent = stamped;
      view.addEventListener('click', function () {
        pre.hidden = !pre.hidden;
        view.textContent = pre.hidden ? 'Voir le code assaini' : 'Masquer le code assaini';
      });
      dl.addEventListener('click', function () {
        var base = srcBaseName(String(result.path).split(' › ').pop());
        download(base + '.clean.' + result.kind, stamped);
      });
      actions.appendChild(view);
      actions.appendChild(dl);
      body.appendChild(actions);
      body.appendChild(pre);
    });

    det.appendChild(body);
    return det;
  }

  /* ------------------------------------------------------------------ *
   * Vérification Backdoor : lecture seule, rien n'est nettoyé ni exporté.
   * ------------------------------------------------------------------ */
  function renderBdcheck(rows, meta) {
    var host = $('bdcheck-result');
    host.textContent = '';
    host.hidden = false;

    var flagged = rows.filter(function (r) { return r.removed.length; });
    var total = rows.reduce(function (n, r) { return n + r.removed.length; }, 0);
    var crit = rows.reduce(function (n, r) { return n + ((r.after && r.after.critical) || 0); }, 0);

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (crit ? 'is-fxap' : total ? 'is-warn' : 'is-ok');
    badge.textContent = total ? total + ' motif(s) suspect(s)' : 'aucune backdoor détectée';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.files + ' fichier(s) vérifié(s) · ' + flagged.length + ' avec motif(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s)' : '');
    head.appendChild(badge);
    head.appendChild(sub);
    host.appendChild(head);

    var answer = document.createElement('p');
    answer.className = 'escrow-answer';
    answer.textContent = !rows.length
      ? 'Rien à vérifier dans ce dépôt.'
      : !total
        ? 'Aucun motif d’exécution système, de sortie réseau, de chargement dynamique, de hook debug ou d’obfuscation détecté. Filtre statique : ce n’est pas une preuve d’innocuité, un code chiffré passe sous le radar.'
        : total + ' motif(s) dangereux dans ' + flagged.length + ' fichier(s) : ouvrez la ligne pour voir lesquels, ou passez le dépôt au nettoyage pour les neutraliser en commentaire.';
    host.appendChild(answer);

    if (!rows.length) return;

    var list = document.createElement('div');
    list.className = 'escrow-list';
    rows.slice(0, 300).forEach(function (r) {
      var row = document.createElement('div');
      row.className = 'escrow-row';
      var name = document.createElement('span');
      name.className = 'escrow-path';
      name.textContent = r.path;
      var chip = document.createElement('span');
      chip.className = 'escrow-state ' + (r.removed.length ? 'is-warn' : 'is-ok');
      chip.textContent = r.removed.length
        ? r.removed.length + ' motif(s) · ' + r.kind.toUpperCase()
        : 'aucun motif · ' + r.kind.toUpperCase();
      if (r.removed.length) {
        row.title = r.removed.map(function (m) {
          return (m.title || m.id || 'motif') + (m.line ? ' (ligne ' + m.line + ')' : '');
        }).join('\n');
      }
      row.appendChild(name);
      row.appendChild(chip);
      list.appendChild(row);
    });
    host.appendChild(list);

    if (rows.length > 300) {
      var more = document.createElement('p');
      more.className = 'limit';
      more.textContent = (rows.length - 300) + ' fichier(s) supplémentaire(s) non listés — le verdict global en tient compte.';
      host.appendChild(more);
    }

    if (flagged.length) {
      var notes = document.createElement('ul');
      notes.className = 'notes';
      flagged.slice(0, 40).forEach(function (r) {
        var li = document.createElement('li');
        li.className = 'warn';
        li.textContent = String(r.path).split(' › ').pop() + ' : ' +
          r.removed.map(function (m) { return m.title || m.id || 'motif'; }).join(', ');
        notes.appendChild(li);
      });
      host.appendChild(notes);
    }
  }

  async function handleBdcheck(payload) {
    var host = $('bdcheck-result');
    var prog = $('bdcheck-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var rows = [];
    var done = 0;
    var skipped = 0;

    while (queue.length && done < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      if (bytes.length > MAX_FILE_BYTES || bytes.subarray(0, 4096).indexOf(0) !== -1) {
        skipped++;
        bytes = null;
        continue;
      }

      prog.textContent = 'Vérification ' + (done + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var text = new TextDecoder('utf-8').decode(bytes);
      bytes = null;
      if (!text.trim()) { skipped++; continue; }

      var res = Sanitize.run(text, item.path);
      rows.push({
        path: item.path,
        kind: res.kind || 'lua',
        removed: res.removed || [],
        after: res.after || { critical: 0, high: 0 }
      });
      done++;
    }

    prog.hidden = true;
    renderBdcheck(rows, { files: done, skipped: skipped });
  }

  var bdcheckBtn = $('bdcheck-btn');
  var bdcheckMenu = $('bdcheck-menu');

  function bdcheckMenuOpen(open) {
    bdcheckMenu.hidden = !open;
    bdcheckBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  bdcheckBtn.addEventListener('click', function (e) {
    e.stopPropagation();
    bdcheckMenuOpen(bdcheckMenu.hidden);
  });

  bdcheckMenu.addEventListener('click', function (e) {
    var choice = e.target.closest('[data-bdcheck-mode]');
    if (!choice) return;
    bdcheckMenuOpen(false);
    $(choice.getAttribute('data-bdcheck-mode') === 'dir' ? 'dir-bdcheck' : 'file-bdcheck').click();
  });

  document.addEventListener('click', function (e) {
    if (bdcheckMenu.hidden) return;
    if (bdcheckBtn.contains(e.target) || bdcheckMenu.contains(e.target)) return;
    bdcheckMenuOpen(false);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !bdcheckMenu.hidden) bdcheckMenuOpen(false);
  });

  ['file-bdcheck', 'dir-bdcheck'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleBdcheck({ entries: null, files: files });
      e.target.value = '';
    });
  });

  function renderSanitize(results, meta) {
    var host = $('sanitize-result');
    host.textContent = '';
    host.hidden = false;

    var removedTotal = results.reduce(function (n, r) { return n + r.removed.length; }, 0);
    var leftCritical = results.reduce(function (n, r) { return n + r.after.critical; }, 0);
    var leftHigh = results.reduce(function (n, r) { return n + r.after.high; }, 0);
    var manualTotal = results.reduce(function (n, r) { return n + r.manual.length; }, 0);

    var head = document.createElement('div');
    head.className = 'report-head';
    var badge = document.createElement('span');
    badge.className = 'verdict ' + (leftCritical ? 'is-warn' : 'is-ok');
    badge.textContent = removedTotal
      ? removedTotal + ' motif(s) neutralisé(s)'
      : 'aucun motif dangereux détecté';
    var sub = document.createElement('span');
    sub.className = 'file-sub';
    sub.textContent = meta.files + ' fichier(s) traité(s) · ' + leftCritical + ' critique(s) et ' +
      leftHigh + ' élevé(s) restant(s)' +
      (meta.skipped ? ' · ' + meta.skipped + ' ignoré(s) (binaire ou trop volumineux)' : '');
    var exportBtn = document.createElement('button');
    exportBtn.type = 'button';
    exportBtn.className = 'btn btn-primary';
    exportBtn.textContent = 'Télécharger le lot nettoyé (.zip)';
    exportBtn.addEventListener('click', function () { exportSanitizeZip(sanitizeResults); });
    head.appendChild(badge);
    head.appendChild(sub);
    head.appendChild(exportBtn);
    host.appendChild(head);

    var notes = [];
    if (manualTotal) notes.push(manualTotal + ' motif(s) étalé(s) sur plusieurs lignes laissé(s) tel quel(s) : à retirer à la main.');
    if (leftCritical) notes.push(leftCritical + ' constat(s) critique(s) subsiste(nt) après nettoyage : relisez ces fichiers avant de les utiliser.');
    if (notes.length) {
      var ul = document.createElement('ul');
      ul.className = 'notes';
      notes.forEach(function (n) {
        var li = document.createElement('li');
        li.className = 'info';
        li.textContent = n;
        ul.appendChild(li);
      });
      host.appendChild(ul);
    }

    var list = document.createElement('div');
    list.className = 'filelist';
    results.forEach(function (r) { list.appendChild(sanitizeCard(r)); });
    host.appendChild(list);
  }

  async function handleSanitizeBatch(payload) {
    var host = $('sanitize-result');
    var prog = $('sanitize-progress');
    host.hidden = true;
    host.textContent = '';

    var entries;
    try {
      prog.hidden = false;
      prog.textContent = 'Lecture du dépôt…';
      entries = await collectFromPayload(payload);
    } catch (e) {
      prog.textContent = 'Lecture impossible : ' + e.message;
      return;
    }
    if (!entries.length) { prog.hidden = true; return; }

    var queue = entries.map(function (e) { return { path: e.path, name: e.file.name, file: e.file }; });
    var results = [];
    var done = 0;
    var skipped = 0;

    while (queue.length && done < MAX_FILES) {
      var item = queue.shift();
      var bytes = item.bytes || null;
      if (!bytes && item.file) {
        try { bytes = await readBytes(item.file); } catch (e) { bytes = null; }
        item.file = null;
      }
      if (!bytes) continue;

      if (isArchiveName(item.name)) {
        await pushArchive(queue, item.path, bytes, 0);
        bytes = null;
        continue;
      }

      if (bytes.length > MAX_FILE_BYTES || bytes.subarray(0, 4096).indexOf(0) !== -1) {
        skipped++;
        bytes = null;
        continue;
      }

      prog.textContent = 'Nettoyage ' + (done + 1) + ' · ' + queue.length + ' en attente · ' + item.path;
      await new Promise(function (r) { setTimeout(r, 0); });

      var text = new TextDecoder('utf-8').decode(bytes);
      bytes = null;
      if (!text.trim()) { skipped++; continue; }

      var res = Sanitize.run(text, item.path);
      res.path = item.path;
      results.push(res);
      done++;
    }

    prog.hidden = true;
    sanitizeResults = results;
    renderSanitize(results, { files: done, skipped: skipped });
  }

  var dzSan = $('dz-sanitize');
  ['dragenter', 'dragover'].forEach(function (ev) {
    dzSan.addEventListener(ev, function (e) { e.preventDefault(); dzSan.classList.add('is-drag'); });
  });
  ['dragleave', 'dragend'].forEach(function (ev) {
    dzSan.addEventListener(ev, function (e) { e.preventDefault(); dzSan.classList.remove('is-drag'); });
  });
  dzSan.addEventListener('drop', function (e) {
    e.preventDefault();
    dzSan.classList.remove('is-drag');
    handleSanitizeBatch(collectDropped(e.dataTransfer));
  });

  ['file-sanitize', 'dir-sanitize'].forEach(function (id) {
    $(id).addEventListener('change', function (e) {
      var files = Array.prototype.slice.call(e.target.files || []);
      if (files.length) handleSanitizeBatch({ entries: null, files: files });
      e.target.value = '';
    });
  });

  $('bc-copy').disabled = true;
  $('bc-download').disabled = true;
})();
