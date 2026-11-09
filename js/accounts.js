/* ------------------------------------------------------------------ *
 * accounts.js — comptes locaux pour CypherDecrypter.
 *
 * Rien ne quitte le navigateur : les comptes sont stockés dans
 * localStorage, les mots de passe en PBKDF2-SHA256 (210 000 tours, sel
 * aléatoire par compte), jamais en clair. Un code de récupération généré
 * à l'inscription permet de réinitialiser le mot de passe : c'est le
 * « mot de passe oublié » d'un site sans serveur ni e-mail.
 * ------------------------------------------------------------------ */
(function (root) {
  'use strict';

  var KEY = 'cypherdecrypter.accounts.v1';
  var ITER = 210000;
  var MIN_PW = 10;
  var MAX_TRIES = 5;
  var LOCK_MS = 60000;
  var SESSION_MS = 30 * 24 * 60 * 60 * 1000;
  var CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  function store() {
    try { return root.localStorage; } catch (err) { return null; }
  }

  function blank() {
    return { users: [], session: null, attempts: {} };
  }

  function read() {
    var ls = store();
    if (!ls) return blank();
    try {
      var raw = ls.getItem(KEY);
      if (!raw) return blank();
      var data = JSON.parse(raw);
      if (!data || !Array.isArray(data.users)) return blank();
      return {
        users: data.users,
        session: data.session || null,
        attempts: data.attempts && typeof data.attempts === 'object' ? data.attempts : {}
      };
    } catch (err) {
      return blank();
    }
  }

  function write(data) {
    var ls = store();
    if (!ls) return false;
    try { ls.setItem(KEY, JSON.stringify(data)); return true; } catch (err) { return false; }
  }

  function secure() {
    return !!(root.crypto && root.crypto.subtle && root.crypto.getRandomValues);
  }

  function bytes(n) {
    var b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  function toB64(buf) {
    var out = '';
    for (var i = 0; i < buf.length; i++) out += String.fromCharCode(buf[i]);
    return root.btoa(out);
  }

  function fromB64(s) {
    var raw = root.atob(String(s));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function derive(password, saltB64) {
    var enc = new TextEncoder();
    return root.crypto.subtle
      .importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
      .then(function (key) {
        return root.crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: fromB64(saltB64), iterations: ITER, hash: 'SHA-256' },
          key,
          256
        );
      })
      .then(function (bits) { return toB64(new Uint8Array(bits)); });
  }

  /* comparaison à durée à peu près constante : évite de fuir un préfixe */
  function same(a, b) {
    var x = String(a || '');
    var y = String(b || '');
    if (x.length !== y.length) return false;
    var diff = 0;
    for (var i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
    return diff === 0;
  }

  function normEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function emailOk(email) {
    return /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(email);
  }

  function makeCode() {
    var raw = bytes(12);
    var out = [];
    for (var i = 0; i < 12; i++) out.push(CODE_ALPHABET[raw[i] % CODE_ALPHABET.length]);
    return 'CD-' + out.slice(0, 4).join('') + '-' + out.slice(4, 8).join('') + '-' + out.slice(8, 12).join('');
  }

  function normCode(code) {
    return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  function publicUser(u) {
    if (!u) return null;
    return { id: u.id, email: u.email, name: u.name || '', createdAt: u.createdAt, provider: u.provider || 'local' };
  }

  function attemptsFor(data, email) {
    var a = data.attempts[email];
    if (!a) return { count: 0, until: 0 };
    return { count: a.count || 0, until: a.until || 0 };
  }

  function lockedFor(data, email) {
    return Math.max(0, attemptsFor(data, email).until - Date.now());
  }

  function current() {
    var data = read();
    if (!data.session) return null;
    if (data.session.at + SESSION_MS < Date.now()) return null;
    var user = data.users.filter(function (u) { return u.id === data.session.id; })[0];
    return user ? publicUser(user) : null;
  }

  function signUp(input) {
    var email = normEmail(input && input.email);
    var password = String((input && input.password) || '');
    var name = String((input && input.name) || '').trim().slice(0, 40);

    if (!secure()) return Promise.resolve({ ok: false, error: 'Contexte sécurisé requis : ouvrez le site en HTTPS ou sur localhost.' });
    if (!emailOk(email)) return Promise.resolve({ ok: false, error: 'Adresse e-mail invalide.' });
    if (password.length < MIN_PW) return Promise.resolve({ ok: false, error: 'Mot de passe trop court : ' + MIN_PW + ' caractères minimum.' });

    var data = read();
    if (data.users.some(function (u) { return u.email === email; })) {
      return Promise.resolve({ ok: false, error: 'Un compte existe déjà avec cette adresse.' });
    }

    var salt = toB64(bytes(16));
    var code = makeCode();
    var codeSalt = toB64(bytes(16));

    return Promise.all([derive(password, salt), derive(normCode(code), codeSalt)]).then(function (hashes) {
      var user = {
        id: 'u_' + toB64(bytes(9)).replace(/[^A-Za-z0-9]/g, ''),
        email: email,
        name: name,
        provider: 'local',
        salt: salt,
        hash: hashes[0],
        recoverySalt: codeSalt,
        recoveryHash: hashes[1],
        createdAt: Date.now(),
        lastLogin: Date.now(),
        iterations: ITER
      };
      var fresh = read();
      fresh.users.push(user);
      fresh.session = { id: user.id, token: toB64(bytes(24)), at: Date.now() };
      delete fresh.attempts[email];
      write(fresh);
      notify();
      return { ok: true, user: publicUser(user), recoveryCode: code };
    });
  }

  function signIn(input) {
    var email = normEmail(input && input.email);
    var password = String((input && input.password) || '');
    if (!secure()) return Promise.resolve({ ok: false, error: 'Contexte sécurisé requis : ouvrez le site en HTTPS ou sur localhost.' });
    if (!emailOk(email) || !password) return Promise.resolve({ ok: false, error: 'Renseignez votre adresse et votre mot de passe.' });

    var data = read();
    var left = lockedFor(data, email);
    if (left > 0) {
      return Promise.resolve({ ok: false, error: 'Trop de tentatives : réessayez dans ' + Math.ceil(left / 1000) + ' s.', lockedFor: left });
    }

    var user = data.users.filter(function (u) { return u.email === email; })[0];
    if (!user) return fail(data, email, 'Adresse ou mot de passe incorrect.');

    return derive(password, user.salt).then(function (hash) {
      if (!same(hash, user.hash)) return fail(read(), email, 'Adresse ou mot de passe incorrect.');
      var fresh = read();
      fresh.session = { id: user.id, token: toB64(bytes(24)), at: Date.now() };
      delete fresh.attempts[email];
      user.lastLogin = Date.now();
      write(fresh);
      notify();
      return { ok: true, user: publicUser(user) };
    });
  }

  function fail(data, email, message) {
    var a = attemptsFor(data, email);
    a.count += 1;
    if (a.count >= MAX_TRIES) {
      a.count = 0;
      a.until = Date.now() + LOCK_MS;
    }
    data.attempts[email] = a;
    write(data);
    return { ok: false, error: message };
  }

  function signOut() {
    var data = read();
    data.session = null;
    write(data);
    notify();
  }

  function recover(input) {
    var email = normEmail(input && input.email);
    var code = normCode(input && input.code);
    var password = String((input && input.password) || '');
    if (!secure()) return Promise.resolve({ ok: false, error: 'Contexte sécurisé requis : ouvrez le site en HTTPS ou sur localhost.' });
    if (password.length < MIN_PW) return Promise.resolve({ ok: false, error: 'Nouveau mot de passe trop court : ' + MIN_PW + ' caractères minimum.' });
    if (!code) return Promise.resolve({ ok: false, error: 'Saisissez le code de récupération affiché à l’inscription.' });

    var data = read();
    var user = data.users.filter(function (u) { return u.email === email; })[0];
    if (!user) return Promise.resolve({ ok: false, error: 'Aucun compte avec cette adresse dans ce navigateur.' });
    if (!user.recoveryHash) return Promise.resolve({ ok: false, error: 'Ce compte n’a pas de code de récupération : créez-en un depuis votre espace compte.' });

    return derive(code, user.recoverySalt).then(function (hash) {
      if (!same(hash, user.recoveryHash)) {
        return { ok: false, error: 'Code de récupération incorrect.' };
      }
      var salt = toB64(bytes(16));
      var nextCode = makeCode();
      var codeSalt = toB64(bytes(16));
      return Promise.all([derive(password, salt), derive(normCode(nextCode), codeSalt)]).then(function (hashes) {
        user.salt = salt;
        user.hash = hashes[0];
        user.recoverySalt = codeSalt;
        user.recoveryHash = hashes[1];
        user.lastLogin = Date.now();
        var fresh = read();
        var target = fresh.users.filter(function (u) { return u.id === user.id; })[0];
        if (target) {
          target.salt = user.salt;
          target.hash = user.hash;
          target.recoverySalt = user.recoverySalt;
          target.recoveryHash = user.recoveryHash;
        }
        fresh.session = { id: user.id, token: toB64(bytes(24)), at: Date.now() };
        delete fresh.attempts[user.email];
        write(fresh);
        notify();
        return { ok: true, recoveryCode: nextCode, user: publicUser(user) };
      });
    });
  }

  function changePassword(input) {
    var oldPw = String((input && input.current) || '');
    var nextPw = String((input && input.next) || '');
    var me = current();
    if (!me) return Promise.resolve({ ok: false, error: 'Connectez-vous d’abord.' });
    if (nextPw.length < MIN_PW) return Promise.resolve({ ok: false, error: 'Nouveau mot de passe trop court : ' + MIN_PW + ' caractères minimum.' });

    var data = read();
    var user = data.users.filter(function (u) { return u.id === me.id; })[0];
    return derive(oldPw, user.salt).then(function (hash) {
      if (!same(hash, user.hash)) return { ok: false, error: 'Mot de passe actuel incorrect.' };
      var salt = toB64(bytes(16));
      return derive(nextPw, salt).then(function (next) {
        var fresh = read();
        var target = fresh.users.filter(function (u) { return u.id === me.id; })[0];
        target.salt = salt;
        target.hash = next;
        write(fresh);
        notify();
        return { ok: true };
      });
    });
  }

  function resetRecovery() {
    var me = current();
    if (!me) return Promise.resolve({ ok: false, error: 'Connectez-vous d’abord.' });
    var code = makeCode();
    var codeSalt = toB64(bytes(16));
    return derive(normCode(code), codeSalt).then(function (hash) {
      var fresh = read();
      var target = fresh.users.filter(function (u) { return u.id === me.id; })[0];
      target.recoverySalt = codeSalt;
      target.recoveryHash = hash;
      write(fresh);
      return { ok: true, recoveryCode: code };
    });
  }

  function notify() {
    if (typeof root.Accounts.onChange === 'function') root.Accounts.onChange();
  }

  root.Accounts = {
    KEY: KEY,
    MIN_PW: MIN_PW,
    MAX_TRIES: MAX_TRIES,
    available: !!store() && secure(),
    current: current,
    signUp: signUp,
    signIn: signIn,
    signOut: signOut,
    recover: recover,
    changePassword: changePassword,
    resetRecovery: resetRecovery,
    onChange: null
  };
})(typeof window !== 'undefined' ? window : globalThis);
