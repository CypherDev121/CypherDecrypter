/* compat.js — correctifs et options charges apres les autres modules.

   Pourquoi ce fichier existe : js/app.js et js/lua54.js sont retelescharges
   depuis la source publiee a chaque synchronisation. Une correction ecrite
   directement dedans serait ecrasee au push suivant. Les correctifs vivent
   donc ici, dans un fichier qui n'est jamais retelecharge, et qui est injecte
   dans index.html au moment du deploiement Pages.

   1. Lua54.parse n'existe pas dans l'API (seul parseChunk est exporte).
      app.js l'appelle deux fois : un .lua compile, ou un bytecode compresse
      dans un conteneur, levait une TypeError avalee par un catch vide, et le
      fichier ressortait "non dechiffre".
   2. AES-ECB etait implemente bloc par bloc via AES-CBC : WebCrypto retire le
      remplissage PKCS#7 de chaque bloc, ce qui detruit le clair (et leve une
      erreur des que le remplissage est invalide, donc presque toujours).
   3. Option d'export : produire une archive sans aucun conteneur escrow.
      L'export est intercepte au niveau de Zip.create, le seul point de
      passage : les autres onglets n'exportent que du texte, la presence d'un
      .lua non lisible signe donc l'export FXAP.

   Tout est rejoue au DOMContentLoaded, pour ne pas dependre de l'ordre des
   balises script : Recover et Zip n'existent pas encore quand ce fichier est
   evalue si sa balise est posee avant eux. */
(function (root) {
  'use strict';

  var doc = (typeof document !== 'undefined') ? document : null;
  var OPT = { removeEscrow: false };

  /* ================================================================ *
   * 1. Alias : Lua54.parse -> Lua54.parseChunk
   * ================================================================ */
  function fixParse() {
    try {
      if (root.Lua54 && typeof root.Lua54.parse !== 'function' &&
          typeof root.Lua54.parseChunk === 'function') {
        root.Lua54.parse = root.Lua54.parseChunk;
      }
    } catch (e) { /* rien a corriger */ }
  }

  /* ================================================================ *
   * 2. AES-ECB : dechiffrement bloc par bloc sans perte
   * ================================================================ */
  function webcrypto() {
    return (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;
  }

  function sigAt(b, i) {
    return b[i] === 0x1b && b[i + 1] === 0x4c && b[i + 2] === 0x75 && b[i + 3] === 0x61;
  }

  /* Clair ECB complet, ou null.

     WebCrypto n'expose pas AES-ECB. On passe donc par AES-CBC avec un IV nul
     sur tout le tampon : CBC donne P_i = D(C_i) XOR C_(i-1), donc
     D(C_i) = P_i XOR C_(i-1) redonne exactement le bloc ECB. Le seul obstacle
     est le remplissage PKCS#7, verifie sur le dernier bloc seulement. On
     ajoute donc un bloc de queue dont on choisit le clair : il faut que
     D(X) XOR C_n = 0x10 x 16 (remplissage complet, toujours accepte), soit
     D(X) = C_n XOR 0x10 x 16, donc X = E(C_n XOR 0x10 x 16). E() s'obtient
     avec le meme chiffrement en CBC sur ce seul bloc. */
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
    } catch (e) {
      return null;
    }

    var last = body.subarray(len - 16);
    var tailPlain = new Uint8Array(16);
    for (var t = 0; t < 16; t++) tailPlain[t] = 0x10 ^ last[t];

    var sealed;
    try {
      sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: zero }, k, tailPlain));
    } catch (e) {
      return null;
    }
    if (sealed.length < 16) return null;

    var buf = new Uint8Array(len + 16);
    buf.set(body, 0);
    buf.set(sealed.subarray(0, 16), len);

    var raw;
    try {
      raw = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: zero }, k, buf));
    } catch (e) {
      return null;
    }
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
        if (mode !== 'ECB') return originalDecrypt.call(R, bytes, options);

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
              } catch (e) {
                lastError = e.message;
              }
            }
          }
        }

        return {
          ok: false,
          reason: 'aucune signature de chunk Lua dans le texte dechiffre (ECB)' +
            (lastError ? ' (' + lastError + ')' : '')
        };
      };
    } catch (e) { /* on laisse les modules d'origine intacts */ }
  }

  /* ================================================================ *
   * 3. Detection des conteneurs escrow
   * ================================================================ */
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

  /* Variante texte : selon l'export, un conteneur peut arriver deja decode en
     chaine (latin-1 ou UTF-8 permissif). Un source Lua normal n'a que des
     tabulations, retours a la ligne et du texte : il ne contient ni marqueur
     FXAP, ni caractere de remplacement, ni caractere de controle. Les accents
     UTF-8 restent du texte et ne declenchent donc rien. */
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

  /* Un conteneur escrow : script .lua ou .fxap dont la charge utile n'est ni du
     bytecode ni du texte lisible, en octets comme en chaine. */
  function isEscrowEntry(entry) {
    if (!entry) return false;
    var name = String(entry.path || '');
    if (!/\.(lua|luac|fxap)$/i.test(name)) return false;
    if (entry.bytes && isEscrowBytes(entry.bytes)) return true;
    if (typeof entry.text === 'string' && isEscrowText(entry.text)) return true;
    return false;
  }

  /* ================================================================ *
   * 4. Nettoyage du fxmanifest
   * ================================================================ */
  /* Retire les references aux fichiers supprimes, sans casser la syntaxe.
     Trois cas :
       - l'entree est dans une table sur une ligne partagee : on l'efface ;
       - l'entree occupait seule sa ligne : la ligne devient vide (une virgule
         orpheline entre { et } serait une erreur de syntaxe Lua) ;
       - la ligne etait une directive a une seule entree (client_script 'x') :
         on commente la ligne entiere. */
  function stripManifest(text, names, total) {
    if (typeof text !== 'string') return text;

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

    // Filet de securite : plus aucune table ne doit commencer par une virgule.
    out = out.replace(/\{[ \t]*,[ \t]*/g, '{').replace(/\n[ \t]*,[ \t]*\n/g, '\n');

    var count = total || removed;
    return '-- [CypherDecrypter] ' + count + ' fichier(s) escrow retire(s) : ' +
      'les scripts correspondants ne sont plus charges.\n' + out;
  }

  /* ================================================================ *
   * 5. Rapports ajoutes dans l'archive
   * ================================================================ */
  function escrowReport(names) {
    var lines = [];
    lines.push('CypherDecrypter - export sans escrow');
    lines.push('');
    lines.push(names.length + ' fichier(s) chiffre(s) par FXAP ont ete retires de cette archive :');
    names.forEach(function (n) { lines.push('- ' + n); });
    lines.push('');
    lines.push('Ce que cela implique, fichier par fichier :');
    lines.push('- leur contenu etait chiffre avec une cle detenue par la plateforme : il n\'a pas ete dechiffre, il a ete ecarte ;');
    lines.push('- les fonctions qu\'ils portaient (elevateurs, chargement d\'IPL, interaction, entitysets) ne sont plus chargees par FiveM ;');
    lines.push('- les lignes correspondantes ont ete retirees des fxmanifest.lua de l\'archive, pour qu\'aucun fichier manquant ne soit reclame au demarrage ;');
    lines.push('- les assets de la map (stream, .ymap, .ytyp) ne sont pas chiffres et restent intacts.');
    lines.push('');
    lines.push('Pour recuperer ces scripts, il faut la version non escrow fournie par l\'auteur de la ressource.');
    return lines.join('\n') + '\n';
  }

  function escrowInfo(dropped) {
    var lines = [];
    lines.push('CypherDecrypter - conteneurs escrow presents dans cette archive');
    lines.push('');
    lines.push(dropped.length + ' fichier(s) chiffre(s) par FXAP sont conserves tels quels :');
    dropped.forEach(function (f) { lines.push('- ' + String(f.path)); });
    lines.push('');
    lines.push('Ils ne sont pas du texte : GitHub, un editeur ou un navigateur les affichera');
    lines.push('comme binaires, c\'est normal. FiveM les dechiffre lui-meme a l\'execution, donc');
    lines.push('la ressource fonctionne si vous les laissez en place.');
    lines.push('');
    lines.push('Pour obtenir une archive sans aucun fichier escrow, cochez l\'option');
    lines.push('"Produire une archive sans aucun fichier escrow" dans l\'onglet');
    lines.push('Clean FXAP & Mapping et relancez l\'export : les conteneurs seront retires');
    lines.push('et les fxmanifest nettoyes. Les scripts concernes ne seront plus charges');
    lines.push('par FiveM, la map et son stream resteront intacts.');
    return lines.join('\n') + '\n';
  }

  /* ================================================================ *
   * 6. Interception de l'export
   * ================================================================ */
  function fixExport() {
    try {
      var Z = root.Zip;
      if (!Z || typeof Z.create !== 'function' || Z.__compatEscrow) return;

      var originalCreate = Z.create;
      Z.__compatEscrow = true;

      Z.create = function (files, opts) {
        try {
          if (!files || !files.length) return originalCreate.apply(Z, arguments);

          var kept = [];
          var dropped = [];
          for (var i = 0; i < files.length; i++) {
            if (isEscrowEntry(files[i])) dropped.push(files[i]);
            else kept.push(files[i]);
          }
          if (!dropped.length) return originalCreate.apply(Z, arguments);

          /* Option desactivee : la liste d'origine est ecrite telle quelle (les
             conteneurs sont conserves) et une note explique la situation. */
          if (!OPT.removeEscrow) {
            return originalCreate.call(Z, files.concat([
              { path: 'ESCROW-INFO.txt', text: escrowInfo(dropped) }
            ]), opts);
          }

          var names = dropped.map(function (f) { return String(f.path); });

          var cleaned = kept.map(function (f) {
            if (!/(^|\/)fxmanifest\.lua$/i.test(String(f.path)) || typeof f.text !== 'string') return f;
            return { path: f.path, text: stripManifest(f.text, names, names.length) };
          });

          cleaned.push({ path: 'ESCROW-RETIRE.txt', text: escrowReport(names) });
          return originalCreate.call(Z, cleaned, opts);
        } catch (e) {
          return originalCreate.apply(Z, arguments);
        }
      };
    } catch (e) { /* export d'origine conserve */ }
  }

  /* ---------------------------------------------------------------- *
   * Interface : case a cocher dans l'onglet Clean FXAP & Mapping
   * ---------------------------------------------------------------- */
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
    cb.style.marginTop = '3px';
    cb.style.flex = '0 0 auto';

    var text = doc.createElement('span');
    text.style.fontSize = '13px';
    text.style.lineHeight = '1.5';

    var title = doc.createElement('strong');
    title.textContent = 'Produire une archive sans aucun fichier escrow';

    var detail = doc.createElement('span');
    detail.style.display = 'block';
    detail.style.opacity = '0.85';
    detail.textContent = 'Les conteneurs chiffres sont retires de l\'archive et le fxmanifest est ' +
      'nettoye : aucun .lua escrow ne reste dedans. Les scripts concernes ne seront ' +
      'plus charges par FiveM (elevateurs, chargement d\'IPL, interaction, entitysets) ; ' +
      'la map et son stream restent intacts. Le detail figure dans ESCROW-RETIRE.txt. ' +
      'Laissee decochee, l\'archive garde les conteneurs et ajoute ESCROW-INFO.txt. ' +
      'Rien ne peut dechiffrer un conteneur escrow sans la cle de l\'auteur : cette ' +
      'option retire les fichiers, elle ne les dechiffre pas.';

    text.appendChild(title);
    text.appendChild(detail);

    cb.addEventListener('change', function () {
      OPT.removeEscrow = !!cb.checked;
      box.style.borderColor = cb.checked ? 'rgba(120, 220, 160, 0.75)' : 'rgba(120, 170, 255, 0.45)';
      box.style.background = cb.checked ? 'rgba(120, 220, 160, 0.10)' : 'rgba(120, 170, 255, 0.07)';
    });

    label.appendChild(cb);
    label.appendChild(text);
    box.appendChild(label);
    dz.parentNode.insertBefore(box, dz.nextSibling);
  }

  /* ================================================================ *
   * Application (idempotente, rejouable apres chargement des modules)
   * ================================================================ */
  function apply() {
    fixParse();
    fixEcb();
    fixExport();
    installUi();
  }

  try {
    if (doc && doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', apply);
    apply();
    if (root.addEventListener) root.addEventListener('load', apply);
  } catch (e) { /* le site reste fonctionnel sans les correctifs */ }

  /* Surface exposee pour les tests automatises. */
  root.CypherEscrow = {
    isEscrowEntry: isEscrowEntry,
    isEscrowBytes: isEscrowBytes,
    isEscrowText: isEscrowText,
    stripManifest: stripManifest,
    set: function (on) { OPT.removeEscrow = !!on; return OPT.removeEscrow; }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
