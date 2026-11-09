/* compat.js — correctifs charges apres les autres modules.

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
      Voir ecbPlain() pour la reconstruction correcte. */
(function (root) {
  'use strict';

  /* ---------------------------------------------------------------- *
   * 1. Alias : Lua54.parse -> Lua54.parseChunk
   * ---------------------------------------------------------------- */
  try {
    if (root.Lua54 && typeof root.Lua54.parse !== 'function' &&
        typeof root.Lua54.parseChunk === 'function') {
      root.Lua54.parse = root.Lua54.parseChunk;
    }
  } catch (e) { /* rien a corriger */ }

  /* ---------------------------------------------------------------- *
   * 2. AES-ECB : dechiffrement bloc par bloc sans perte
   * ---------------------------------------------------------------- */
  try {
    var R = root.Recover;
    var L = root.Lua54;
    if (!R || typeof R.decrypt !== 'function' || typeof R.payloadRegions !== 'function') return;
    if (R.__compatEcb) return;

    var originalDecrypt = R.decrypt;
    R.__compatEcb = true;

    function webcrypto() {
      return (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;
    }

    function sigAt(b, i) {
      return b[i] === 0x1b && b[i + 1] === 0x4c && b[i + 2] === 0x75 && b[i + 3] === 0x61;
    }

    /* Clair ECB complet, ou null.

       WebCrypto n'expose pas AES-ECB. On passe donc par AES-CBC avec un IV
       nul sur tout le tampon : CBC donne P_i = D(C_i) XOR C_(i-1), donc
       D(C_i) = P_i XOR C_(i-1) redonne exactement le bloc ECB. Le seul
       obstacle est le remplissage PKCS#7, verifie sur le dernier bloc
       seulement. On ajoute donc un bloc de queue dont on choisit le clair :
       il faut que D(X) XOR C_n = 0x10 x 16 (remplissage complet, toujours
       accepte), soit D(X) = C_n XOR 0x10 x 16, donc X = E(C_n XOR 0x10 x 16).
       E() s'obtient avec le meme chiffrement en CBC sur ce seul bloc. */
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
        /* ECB n'a pas d'IV : on teste le debut de la charge, puis un
           eventuel prefixe de 16 octets reste en clair. */
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
})(typeof globalThis !== 'undefined' ? globalThis : this);
