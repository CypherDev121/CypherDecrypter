/* compat.js — correctifs et options charges apres les autres modules.

   app.js et lua54.js sont retelescharges depuis la source publiee a chaque
   synchronisation : une correction ecrite dedans serait ecrasee. Tout vit donc
   ici, et ce fichier est injecte dans index.html au deploiement Pages.

   1. Lua54.parse n'existe pas (seul parseChunk est exporte) : app.js l'appelle
      deux fois, la TypeError etait avalee par un catch vide.
   2. AES-ECB passait par AES-CBC bloc par bloc : WebCrypto retire le
      remplissage PKCS#7, ce qui detruit le clair et leve une erreur.
   3. Export sans escrow, actif par defaut et sans intervention : intercepte au
      niveau de Zip.create, le seul point de passage de l'export.

   Rejoue au DOMContentLoaded : Recover et Zip n'existent pas forcement quand
   ce fichier est evalue. */
(function (root) {
  'use strict';

  var doc = (typeof document !== 'undefined') ? document : null;
  var OPT = { removeEscrow: true };
  var STORE = 'cypherdecrypter.noEscrow';

  /* ---------------- 1. alias Lua54.parse ---------------- */
  function fixParse() {
    try {
      if (root.Lua54 && typeof root.Lua54.parse !== 'function' &&
          typeof root.Lua54.parseChunk === 'function') {
        root.Lua54.parse = root.Lua54.parseChunk;
      }
    } catch (e) { /* rien a corriger */ }
  }

  /* ---------------- 2. AES-ECB sans perte ----------------
     CBC sur tout le tampon donne P_i = D(C_i) XOR C_(i-1), donc
     D(C_i) = P_i XOR C_(i-1) redonne le bloc ECB. Le remplissage PKCS#7 est
     verifie sur le dernier bloc : on ajoute un bloc de queue dont le clair est
     force a 0x10 x 16, donc X = E(C_n XOR 0x10 x 16). */
  function webcrypto() {
    return (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;
  }

  function sigAt(b, i) {
    return b[i] === 0x1b && b[i + 1] === 0x4c && b[i + 2] === 0x75 && b[i + 3] === 0x61;
  }

  async function ecbPlain(input, key) {
    var subtle = webcrypto();
    if (!subtle) return null;
    var len = input.length - (input.length % 16);
    if (len < 32) return null;
    var body = input.subarray(0, len);
    var zero = new Uint8Array(16);
    var k;

    try {
      k = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt', 'encrypt']);
    } catch (e) { return null; }

    var last = body.subarray(len - 16);
    var tailPlain = new Uint8Array(16);
    for (var t = 0; t < 16; t++) tailPlain[t] = 0x10 ^ last[t];

    var sealed;
    try {
      sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: zero }, k, tailPlain));
    } catch (e) { return null; }
    if (sealed.length < 16) return null;

    var buf = new Uint8Array(len + 16);
    buf.set(body, 0);
    buf.set(sealed.subarray(0, 16), len);

    var raw;
    try {
      raw = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: zero }, k, buf));
    } catch (e) { return null; }
    if (raw.length < len) return null;

    var out = new Uint8Array(len);
    for (var b = 0; b < len; b += 16) {
      for (var j = 0; j < 16; j++) {
        var prev = b === 0 ? 0 : body[b - 16 + j];
        out[b + j] = raw[b + j] ^ prev;
      }
    }
    return out;
  }

  function fixEcb() {
    try {
      var R = root.Recover;
      var L = root.Lua54;
      if (!R || typeof R.decrypt !== 'function' || typeof R.payloadRegions !== 'function') return;
      if (R.__compatEcb) return;

      var originalDecrypt = R.decrypt;
      R.__compatEcb = true;

      R.decrypt = async function (bytes, options) {
        options = options || {};
        var mode = options.mode || 'CBC';
        /* un vrai conteneur FXAP relève des layouts embarqués (IV dans
           l'en-tête) : on laisse Recover décider du mode, même si ECB est
           demandé. */
        var isFxap = bytes && bytes.length > 4 && bytes[0] === 0x46 && bytes[1] === 0x58 &&
          bytes[2] === 0x41 && bytes[3] === 0x50;
        if (mode !== 'ECB' || isFxap) return originalDecrypt.call(R, bytes, options);

        var Lua = options.lua || L;
        var key = options.key;
        if (!Lua || typeof Lua.parseChunk !== 'function') {
          return { ok: false, reason: 'moteur Lua54 absent' };
        }
        if (!key || [16, 24, 32].indexOf(key.length) === -1) {
          return { ok: false, reason: 'cle invalide : 16, 24 ou 32 octets attendus' };
        }

        var regions = R.payloadRegions(bytes);
        var lastError = null;

        for (var ri = 0; ri < regions.length; ri++) {
          var region = regions[ri];
          var starts = [region];
          if (region + 16 < bytes.length) starts.push(region + 16);

          for (var si = 0; si < starts.length; si++) {
            var start = starts[si];
            if (start >= bytes.length) continue;
            var plain = await ecbPlain(bytes.subarray(start), key);
            if (!plain) continue;

            for (var h = 0; h + 4 <= plain.length; h++) {
              if (!sigAt(plain, h)) continue;
              try {
                var parsed = Lua.parseChunk(plain.subarray(h));
                return {
                  ok: true,
                  offset: start + h,
                  data: plain.subarray(h, h + parsed.bytesUsed),
                  parsed: parsed,
                  mode: 'ECB',
                  ivLabel: 'sans IV'
                };
              } catch (e) { lastError = e.message; }
            }
          }
        }

        return {
          ok: false,
          reason: 'aucune signature de chunk Lua dans le texte dechiffre (ECB)' +
            (lastError ? ' (' + lastError + ')' : '')
        };
      };
    } catch (e) { /* modules d'origine intacts */ }
  }

  /* ---------------- 3. detection des conteneurs escrow ---------------- */
  function entropyOf(b) {
    var n = Math.min(b.length, 8192);
    if (!n) return 0;
    var counts = new Array(256).fill(0);
    for (var i = 0; i < n; i++) counts[b[i]]++;
    var h = 0;
    for (var j = 0; j < 256; j++) {
      if (!counts[j]) continue;
      var p = counts[j] / n;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function hasFxapMarker(b) {
    var head = Math.min(b.length, 4096);
    for (var i = 0; i + 4 <= head; i++) {
      if (b[i] === 0x46 && b[i + 1] === 0x58 && b[i + 2] === 0x41 && b[i + 3] === 0x50) return true;
    }
    return false;
  }

  function isEscrowBytes(b) {
    if (!b || b.length < 32) return false;
    if (sigAt(b, 0)) return false;

    var n = Math.min(b.length, 4096);
    var printable = 0;
    for (var i = 0; i < n; i++) {
      var c = b[i];
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
    }
    if (printable / n > 0.9) return false;

    return hasFxapMarker(b) || entropyOf(b) > 7.4;
  }

  /* Variante texte : un conteneur peut arriver deja decode en chaine. Une
     source Lua n'a ni marqueur FXAP, ni caractere de remplacement, ni
     caractere de controle ; les accents UTF-8 restent du texte. */
  function isEscrowText(t) {
    if (typeof t !== 'string' || t.length < 32) return false;
    if (t.slice(0, 4) === '\u001bLua') return false;
    if (t.slice(0, 2000).indexOf('FXAP') !== -1) return true;
    if (t.indexOf('\uFFFD') !== -1) return true;

    var n = Math.min(t.length, 4096);
    var ctrl = 0;
    for (var i = 0; i < n; i++) {
      var c = t.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13) continue;
      if (c < 32 || (c >= 0x7f && c <= 0x9f)) ctrl++;
    }
    return ctrl / n > 0.02;
  }

  function isEscrowEntry(entry) {
    if (!entry) return false;
    var name = String(entry.path || '');
    if (!/\.(lua|luac|fxap)$/i.test(name)) return false;
    if (entry.bytes && isEscrowBytes(entry.bytes)) return true;
    if (typeof entry.text === 'string' && isEscrowText(entry.text)) return true;
    return false;
  }

  /* Le .fxap de la ressource part toujours avec les conteneurs : c'est le
     manifeste du conteneur, sans objet quand les scripts chiffres sont retires.
     Il ne doit donc plus etre signale comme un fichier illisible a relancer. */
  function isEscrowForRemoval(entry) {
    if (isEscrowEntry(entry)) return true;
    var name = String((entry && entry.path) || '');
    return /(^|\/)[^/]*\.fxap$/i.test(name);
  }

  /* ---------------- 4. bloc escrow_ignore ----------------
     Dans un manifeste escrow, escrow_ignore liste les fichiers laisses en
     clair. En export sans escrow on les retire aussi : l'utilisateur ne
     veut garder ni le chiffre ni la version lisible des scripts. Le
     fxmanifest lui-meme n'est jamais retire (la ressource mourrait). */
  function parseEscrowIgnore(text) {
    var globs = [];
    if (typeof text !== 'string') return globs;
    var re = /escrow_ignore\s*\{([^}]*)\}/g;
    var m;
    while ((m = re.exec(text))) {
      var q = /['"]([^'"]+)['"]/g, mm;
      while ((mm = q.exec(m[1]))) globs.push(mm[1]);
    }
    var re2 = /escrow_ignore\s+['"]([^'"]+)['"]/g;
    while ((m = re2.exec(text))) globs.push(m[1]);
    return globs;
  }

  /* Les motifs sont relatifs a la racine de la ressource ; le chemin de
     l'entree peut etre prefixe (dossier depose, archive). On compare sur
     le suffixe. '*' devient '.*'. */
  function ignoreHit(path, globs) {
    var p = '/' + String(path || '').replace(/\\/g, '/').replace(/^\/+/, '');
    for (var i = 0; i < globs.length; i++) {
      var g = String(globs[i]);
      if (/^(fxmanifest\.lua|__resource\.lua)$/i.test(g)) continue;
      var rx = g.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
      if (new RegExp('/' + rx + '$', 'i').test(p)) return g;
    }
    return null;
  }

  function isEscrowIgnored(entry, globs) {
    if (!entry || !globs || !globs.length) return false;
    var p = String(entry.path || '');
    if (/(^|\/)(fxmanifest|__resource)\.lua$/i.test(p)) return false;
    return !!ignoreHit(p, globs);
  }

  /* Le bloc escrow_ignore est commente dans le manifeste nettoye : il ne
     pointe que des fichiers retires et n'a plus d'objet hors escrow. */
  function stripEscrowIgnore(text) {
    var out = [];
    var depth = 0;
    var hit = false;
    var lines = String(text).split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!depth && /escrow_ignore/i.test(line)) {
        hit = true;
        depth = Math.max(0, (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length);
        out.push('-- retire par CypherDecrypter (escrow_ignore sans objet hors escrow) : ' + line.trim());
        continue;
      }
      if (depth) {
        depth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
        if (depth < 0) depth = 0;
        out.push(line.trim() ? '-- ' + line : '');
        continue;
      }
      out.push(line);
    }
    return { text: out.join('\n'), hit: hit };
  }

  /* ---------------- 5. nettoyage du fxmanifest ---------------- */
  function stripManifest(text, names, total) {
    if (typeof text !== 'string') return text;

    var ig = stripEscrowIgnore(text);
    if (ig.hit) text = ig.text;

    var wanted = {};
    (names || []).forEach(function (p) {
      var base = String(p).split('/').pop().toLowerCase();
      wanted[base] = String(p);
    });

    var removed = 0;
    var out = text.split(/\r?\n/).map(function (line) {
      if (line.indexOf('--') === 0) return line;

      var touched = false;
      var cleaned = line.replace(/(['"])([^'"]+)\1/g, function (m, q, v) {
        var base = String(v).split('/').pop().toLowerCase();
        if (!wanted[base]) return m;
        touched = true;
        removed++;
        return '';
      });

      if (!touched) return line;

      cleaned = cleaned.replace(/,\s*,/g, ',').replace(/\{\s*,/g, '{').replace(/,\s*\}/g, ' }');
      if (/['"]/.test(cleaned)) return cleaned.replace(/[ \t]+$/, '');
      if (/(script|files?)\b/i.test(cleaned)) {
        return '-- retire par CypherDecrypter (fichier escrow supprime) : ' + line.trim();
      }
      return '';
    }).join('\n');

    out = out.replace(/\{[ \t]*,[ \t]*/g, '{').replace(/\n[ \t]*,[ \t]*\n/g, '\n');

    var count = total || removed;
    return '-- [CypherDecrypter] ' + count + ' fichier(s) escrow retire(s) : ' +
      'les scripts correspondants ne sont plus charges.\n' + out;
  }

  /* ---------------- 5. rapports de l'archive ---------------- */
  function escrowReport(names, ignored) {
    var lines = [];
    lines.push('CypherDecrypter - export sans escrow (automatique)');
    lines.push('');
    lines.push(names.length + ' fichier(s) escrow ont ete retires de cette archive :');
    names.forEach(function (n) { lines.push('- ' + n); });
    if (ignored && ignored.length) {
      lines.push('');
      lines.push(ignored.length + ' fichier(s) en clair listes par escrow_ignore ont aussi ete retires :');
      ignored.forEach(function (n) { lines.push('- ' + n); });
    }
    lines.push('');
    lines.push('Ce que cela implique, fichier par fichier :');
    lines.push('- leur contenu etait chiffre avec une cle detenue par la plateforme : il n\'a pas ete dechiffre, il a ete ecarte ;');
    lines.push('- les fonctions qu\'ils portaient (elevateurs, chargement d\'IPL, interaction, entitysets) ne sont plus chargees par FiveM ;');
    lines.push('- les lignes correspondantes ont ete retirees des fxmanifest.lua de l\'archive, pour qu\'aucun fichier manquant ne soit reclame au demarrage ;');
    lines.push('- les assets de la map (stream, .ymap, .ytyp) ne sont pas chiffres et restent intacts ;');
    lines.push('- le .fxap de la ressource (manifeste du conteneur) est retire aussi : sans les scripts chiffres il ne sert plus a rien.');
    lines.push('');
    lines.push('Ce retrait est automatique. Pour conserver les conteneurs et laisser FiveM');
    lines.push('les dechiffrer lui-meme, decochez l\'option dans l\'onglet Clean FXAP & Mapping.');
    lines.push('Pour recuperer ces scripts en clair, il faut la version non escrow de l\'auteur.');
    return lines.join('\n') + '\n';
  }

  function escrowInfo(dropped) {
    var lines = [];
    lines.push('CypherDecrypter - conteneurs escrow conserves (option desactivee)');
    lines.push('');
    lines.push(dropped.length + ' fichier(s) chiffre(s) par FXAP sont conserves tels quels :');
    dropped.forEach(function (f) { lines.push('- ' + String(f.path)); });
    lines.push('');
    lines.push('Ils ne sont pas du texte : GitHub, un editeur ou un navigateur les affichera');
    lines.push('comme binaires, c\'est normal. FiveM les dechiffre lui-meme a l\'execution, donc');
    lines.push('la ressource fonctionne si vous les laissez en place.');
    lines.push('');
    lines.push('Le retrait est actif par defaut : ici l\'option a ete decochee volontairement.');
    lines.push('Recochez-la dans l\'onglet Clean FXAP & Mapping pour produire une archive');
    lines.push('sans aucun fichier escrow.');
    return lines.join('\n') + '\n';
  }

  /* Le rapport produit par app.js decrit l'archive qu'il croyait ecrire : il
     annonce les conteneurs recopies et reclame un nouvel essai pour le .fxap
     illisible. En mode sans escrow, ces deux phrases sont fausses. */
  function rewriteFxapReport(text, stats) {
    if (typeof text !== 'string') return text;
    if (!stats || !stats.removed) return text;

    var touched = false;
    var out = text.split(/\r?\n/).map(function (line) {
      var t = line.trim();
      if (/conteneur\(s\) FXAP encore chiffr/i.test(t)) {
        touched = true;
        return 'Aucun conteneur FXAP chiffre ne reste dans cette archive : ' + stats.removed +
          ' fichier(s) escrow ont ete retires' +
          (stats.fxap ? ' (dont le .fxap de la ressource)' : '') +
          '. La liste exacte figure dans ESCROW-RETIRE.txt.';
      }
      if (/ne peuvent pas [e\u00ea]tre export[\u00e9e]s/i.test(t)) {
        touched = true;
        return 'Aucun fichier utile n\'a ete perdu : les .fxap et les conteneurs illisibles ' +
          'font partie du conteneur escrow et sont sans objet dans une archive sans escrow.';
      }
      return line;
    }).join('\n');

    return touched ? out : text;
  }

  /* ---------------- 6. interception de l'export ---------------- */
  function fixExport() {
    try {
      var Z = root.Zip;
      if (!Z || typeof Z.create !== 'function' || Z.__compatEscrow) return;

      var originalCreate = Z.create;
      Z.__compatEscrow = true;

      Z.create = function (files, opts) {
        try {
          if (!files || !files.length) return originalCreate.apply(Z, arguments);

          /* Les fichiers listes par escrow_ignore dans le manifeste du lot
             sont retires eux aussi (sans escrow = plus aucun script). */
          var ignoreGlobs = [];
          for (var gi = 0; gi < files.length; gi++) {
            var fx = files[gi];
            if (/(^|\/)fxmanifest\.lua$/i.test(String(fx.path)) && typeof fx.text === 'string') {
              ignoreGlobs = ignoreGlobs.concat(parseEscrowIgnore(fx.text));
            }
          }

          var kept = [];
          var dropped = [];
          for (var i = 0; i < files.length; i++) {
            var f = files[i];
            var drop = OPT.removeEscrow
              ? (isEscrowForRemoval(f) || isEscrowIgnored(f, ignoreGlobs))
              : isEscrowEntry(f);
            if (drop) dropped.push(f); else kept.push(f);
          }
          if (!dropped.length) return originalCreate.apply(Z, arguments);

          /* Option desactivee a la main : liste d'origine ecrite telle quelle. */
          if (!OPT.removeEscrow) {
            return originalCreate.call(Z, files.concat([
              { path: 'ESCROW-INFO.txt', text: escrowInfo(dropped) }
            ]), opts);
          }

          var escrowNames = dropped.filter(function (x) { return !isEscrowIgnored(x, ignoreGlobs) || isEscrowForRemoval(x); })
            .map(function (x) { return String(x.path); });
          var ignoredNames = dropped.filter(function (x) { return isEscrowIgnored(x, ignoreGlobs) && !isEscrowForRemoval(x); })
            .map(function (x) { return String(x.path); });
          var names = escrowNames.concat(ignoredNames);
          var stats = { removed: names.length, fxap: false };
          for (var d = 0; d < dropped.length; d++) {
            if (/\.fxap$/i.test(String(dropped[d].path))) stats.fxap = true;
          }

          var cleaned = kept.map(function (x) {
            var p = String(x.path || '');
            if (/(^|\/)fxmanifest\.lua$/i.test(p) && typeof x.text === 'string') {
              return { path: x.path, text: stripManifest(x.text, names, names.length) };
            }
            if (typeof x.text === 'string') {
              var rw = rewriteFxapReport(x.text, stats);
              if (rw !== x.text) return { path: x.path, text: rw };
            }
            return x;
          });

          cleaned.push({ path: 'ESCROW-RETIRE.txt', text: escrowReport(escrowNames, ignoredNames) });
          return originalCreate.call(Z, cleaned, opts);
        } catch (e) {
          return originalCreate.apply(Z, arguments);
        }
      };
    } catch (e) { /* export d'origine conserve */ }
  }

  /* ---------------- 7. interface ---------------- */
  /* Le retrait est actif par defaut. Le stockage ne sert qu'a retenir un
     desaccordement volontaire (valeur '0'). */
  function loadPref() {
    try {
      var v = root.localStorage ? root.localStorage.getItem(STORE) : null;
      OPT.removeEscrow = (v !== '0');
    } catch (e) {
      OPT.removeEscrow = true;
    }
  }

  function savePref(on) {
    try {
      if (root.localStorage) root.localStorage.setItem(STORE, on ? '1' : '0');
    } catch (e) { /* stockage indisponible */ }
  }

  function paint(box, cb) {
    box.style.borderColor = cb.checked ? 'rgba(120, 220, 160, 0.75)' : 'rgba(120, 170, 255, 0.45)';
    box.style.background = cb.checked ? 'rgba(120, 220, 160, 0.10)' : 'rgba(120, 170, 255, 0.07)';
  }

  function installUi() {
    if (!doc || doc.getElementById('fxap-no-escrow')) return;
    var dz = doc.getElementById('dz-fxap');
    if (!dz || !dz.parentNode) return;

    var box = doc.createElement('div');
    box.id = 'fxap-no-escrow-box';
    box.style.margin = '14px 0 0';
    box.style.padding = '12px 14px';
    box.style.border = '1px solid rgba(120, 170, 255, 0.45)';
    box.style.borderRadius = '10px';
    box.style.background = 'rgba(120, 170, 255, 0.07)';

    var label = doc.createElement('label');
    label.style.display = 'flex';
    label.style.gap = '10px';
    label.style.alignItems = 'flex-start';
    label.style.cursor = 'pointer';

    var cb = doc.createElement('input');
    cb.type = 'checkbox';
    cb.id = 'fxap-no-escrow';
    cb.checked = OPT.removeEscrow;
    cb.style.marginTop = '3px';
    cb.style.flex = '0 0 auto';

    var text = doc.createElement('span');
    text.style.fontSize = '13px';
    text.style.lineHeight = '1.5';

    var title = doc.createElement('strong');
    title.textContent = 'Archive sans aucun fichier escrow (actif par defaut)';

    var detail = doc.createElement('span');
    detail.style.display = 'block';
    detail.style.opacity = '0.85';
    detail.textContent = 'Rien a faire : les conteneurs chiffres et le .fxap de la ressource ' +
      'sont retires de chaque export, les fxmanifest sont nettoyes, aucun fichier escrow ' +
      'ne reste dans l\'archive. Les scripts concernes ne seront plus charges par FiveM ' +
      '(elevateurs, chargement d\'IPL, interaction, entitysets) ; la map et son stream ' +
      'restent intacts. Detail dans ESCROW-RETIRE.txt. Decoche cette case uniquement si ' +
      'tu veux garder les conteneurs et laisser FiveM les dechiffrer lui-meme. Rien ne ' +
      'peut dechiffrer un conteneur escrow sans la cle de l\'auteur : ce mode retire les ' +
      'fichiers, il ne les dechiffre pas.';

    text.appendChild(title);
    text.appendChild(detail);

    cb.addEventListener('change', function () {
      OPT.removeEscrow = !!cb.checked;
      savePref(OPT.removeEscrow);
      paint(box, cb);
    });

    label.appendChild(cb);
    label.appendChild(text);
    box.appendChild(label);
    dz.parentNode.insertBefore(box, dz.nextSibling);
    paint(box, cb);
  }

  /* ---------------- application ---------------- */
  function apply() {
    loadPref();
    fixParse();
    fixEcb();
    fixExport();
    installUi();
    if (doc) {
      var cb = doc.getElementById('fxap-no-escrow');
      if (cb) {
        cb.checked = OPT.removeEscrow;
        paint(doc.getElementById('fxap-no-escrow-box'), cb);
      }
    }
  }

  try {
    if (doc && doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', apply);
    apply();
    if (root.addEventListener) root.addEventListener('load', apply);
  } catch (e) { /* le site reste fonctionnel sans les correctifs */ }

  root.CypherEscrow = {
    isEscrowEntry: isEscrowEntry,
    isEscrowBytes: isEscrowBytes,
    isEscrowText: isEscrowText,
    isEscrowForRemoval: isEscrowForRemoval,
    isEscrowIgnored: isEscrowIgnored,
    parseEscrowIgnore: parseEscrowIgnore,
    stripEscrowIgnore: stripEscrowIgnore,
    stripManifest: stripManifest,
    rewriteFxapReport: rewriteFxapReport,
    set: function (on) { OPT.removeEscrow = !!on; return OPT.removeEscrow; },
    get: function () { return OPT.removeEscrow; }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
