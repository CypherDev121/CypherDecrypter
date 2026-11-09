/* Verification automatique du decryptage et de l'export.

   Execute par .github/workflows/verify-decrypt.yml : `node tests/verify-decrypt.cjs`.
   Aucun navigateur : les modules sont charges dans un contexte vm, comme le
   serait le site, et le chunk de reference est compile par luac5.4. */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const LUAC = process.env.LUAC_PATH || '/tmp/a.luac';
const MANIFEST_OUT = '/tmp/manifest-out.lua';

const ctx = {
  console, TextDecoder, TextEncoder, Uint8Array, ArrayBuffer, DataView,
  Math, Date, Promise, BigInt, JSON, String, Number, Object, Array,
  Error, RegExp, Set, Map, Buffer, Blob, Response, DecompressionStream,
  crypto: nodeCrypto.webcrypto
};
ctx.globalThis = ctx;
vm.createContext(ctx);

for (const f of ['lua54.js', 'decompile.js', 'recover.js', 'zip.js', 'compat.js']) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'js', f), 'utf8'), ctx, { filename: f });
}

const L = ctx.Lua54;
const R = ctx.Recover;
const CE = ctx.CypherEscrow;
let fails = 0;

function check(name, cond, extra) {
  if (cond) {
    console.log('OK   ' + name);
  } else {
    console.log('FAIL ' + name + (extra ? ' :: ' + String(extra) : ''));
    fails++;
  }
}

(async function main() {
  if (!L || !R) throw new Error('modules Lua54/Recover absents du contexte');

  check('Lua54.parseChunk est expose', typeof L.parseChunk === 'function');
  check('Lua54.parse est expose (correctif)', typeof L.parse === 'function');
  check('Recover.decrypt est expose', typeof R.decrypt === 'function');
  check('filtre escrow expose', !!(CE && typeof CE.isEscrowEntry === 'function'));
  if (!CE) throw new Error('CypherEscrow absent : compat.js n a pas termine son evaluation');
  check('le retrait escrow est actif par defaut', CE.get() === true);

  const bytes = new Uint8Array(fs.readFileSync(LUAC));

  let viaParse = null;
  try { viaParse = L.parse(bytes); } catch (e) { console.log('err parse: ' + e.message); }
  check('Lua54.parse lit un vrai .luac', !!(viaParse && viaParse.main));

  let code = '';
  if (viaParse && viaParse.main) {
    try { code = L.decompile(viaParse.main, { fileName: 'a.luac' }).code; } catch (e) { console.log('err decompile: ' + e.message); }
  }
  check('decompilation produite', code.length > 20, code.slice(0, 60));

  const key = nodeCrypto.randomBytes(16);
  const keyBytes = new Uint8Array(key);

  const ec = nodeCrypto.createCipheriv('aes-128-ecb', key, null);
  const ecbCipher = new Uint8Array(Buffer.concat([ec.update(Buffer.from(bytes)), ec.final()]));

  const rotEcb = await R.decrypt(ecbCipher, { key: keyBytes, mode: 'ECB', lua: L });
  check('AES-ECB dechiffre le chunk', !!(rotEcb && rotEcb.ok === true), rotEcb && rotEcb.reason);
  if (rotEcb && rotEcb.ok) {
    const same = Buffer.compare(
      Buffer.from(rotEcb.data),
      Buffer.from(bytes.subarray(0, rotEcb.data.length))
    ) === 0;
    check('AES-ECB rend exactement le clair', same);
  }

  const cb = nodeCrypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
  const cbcCipher = new Uint8Array(Buffer.concat([cb.update(Buffer.from(bytes)), cb.final()]));
  const rotCbc = await R.decrypt(cbcCipher, { key: keyBytes, mode: 'CBC', iv: new Uint8Array(16), lua: L });
  check('AES-CBC dechiffre toujours', !!(rotCbc && rotCbc.ok === true), rotCbc && rotCbc.reason);

  const encContainer = new Uint8Array(Buffer.concat([
    Buffer.from('FXAP'), nodeCrypto.randomBytes(400)
  ]));
  const escrowEntry = { path: 'client/activate_ipl.lua', bytes: encContainer };

  check('conteneur chiffre (octets) reconnu', CE.isEscrowEntry(escrowEntry) === true);
  check('conteneur chiffre (texte mojibake) reconnu',
    CE.isEscrowEntry({ path: 'client/Elevator.lua', text: 'FXAP' + '\uFFFD'.repeat(80) }) === true);
  check('conteneur chiffre (texte latin-1) reconnu',
    CE.isEscrowEntry({ path: 'client/interaction.lua', text: '\u0001\u0002\u0080\u009f'.repeat(40) }) === true);
  check('source .lua conservee', CE.isEscrowEntry({ path: 'client/x.lua', bytes: new Uint8Array(Buffer.from('local a = 1\nprint(a)\n')) }) === false);
  check('source .lua accentuee conservee',
    CE.isEscrowEntry({ path: 'client/y.lua', text: '-- commentaire accentue : deja vu, ca marche\nlocal s = "text"\n' }) === false);
  check('bytecode conserve', CE.isEscrowEntry({ path: 'client/y.lua', bytes }) === false);
  check('asset .ymap non touche', CE.isEscrowEntry({ path: 'stream/a.ymap', bytes: encContainer }) === false);

  const mani = "fx_version 'cerulean'\nclient_scripts {\n  'client/activate_ipl.lua',\n  'client/other.lua'\n}\nclient_script 'client/Elevator.lua'\n";
  const maniOut = CE.stripManifest(mani, ['client/activate_ipl.lua', 'client/Elevator.lua'], 2);

  const active = maniOut.split('\n').filter((l) => {
    const t = l.trim();
    if (t.indexOf('--') === 0) return false;
    return /(client|server|shared)_scripts?\s+['"]/.test(t) || /activate_ipl|Elevator/.test(t);
  });
  check('manifeste : plus aucune reference active', active.length === 0, active.join(' | '));
  check('manifeste : directive orpheline commentee', /^-- retire[^\n]*Elevator/m.test(maniOut));
  check('manifeste : entree voisine gardee', maniOut.indexOf('client/other.lua') !== -1, maniOut);
  check('manifeste : pas de virgule orpheline', !/\{\s*,/.test(maniOut) && !/\n\s*,/.test(maniOut), maniOut);

  fs.writeFileSync(MANIFEST_OUT, maniOut);
  let luaOk = true;
  let luaErr = '';
  try {
    execFileSync('lua5.4', ['-e', 'assert(loadfile("' + MANIFEST_OUT + '"))'], { stdio: 'pipe' });
  } catch (e) {
    luaOk = false;
    luaErr = (e.stderr ? e.stderr.toString() : e.message).trim();
  }
  check('manifeste nettoye = Lua valide', luaOk, luaErr);

  if (typeof ctx.Zip.create !== 'function' || typeof ctx.Zip.entries !== 'function') {
    throw new Error('API Zip incomplete');
  }

  /* ---------------- mode automatique (defaut) ---------------- */
  const reportSrc = [
    'CypherDecrypter - Clean FXAP & Mapping',
    "1 fichier(s) ne peuvent pas etre exportes (lecture impossible ou budget memoire depasse) : tstudio_zmapdata/.fxap",
    "27 conteneur(s) FXAP encore chiffre(s) sont recopies tels quels sous leur nom d'origine.",
    ''
  ].join('\n');

  // Aucun appel a set() : on exporte tel quel, comme le fait le site au chargement.
  const zOn = ctx.Zip.create([
    escrowEntry,
    { path: 'tstudio_zmapdata/.fxap', bytes: new Uint8Array(8) },
    { path: 'stream/a.ymap', bytes: encContainer },
    { path: 'fxmanifest.lua', text: mani },
    { path: 'CYPHERDECRYPTER.txt', text: reportSrc }
  ], { comment: 'test' });
  check('zip sans escrow : octets produits', zOn instanceof Uint8Array && zOn.length > 0);

  const listed = await ctx.Zip.entries(zOn);
  const names = listed.map((e) => e.name);
  check('sans cocher : conteneur absent', names.indexOf('client/activate_ipl.lua') === -1, names.join(', '));
  check('sans cocher : .fxap retire', names.indexOf('tstudio_zmapdata/.fxap') === -1, names.join(', '));
  check('sans cocher : asset present', names.indexOf('stream/a.ymap') !== -1, names.join(', '));
  check('sans cocher : rapport present', names.indexOf('ESCROW-RETIRE.txt') !== -1, names.join(', '));
  check('sans cocher : pas de note informative', names.indexOf('ESCROW-INFO.txt') === -1, names.join(', '));

  const maniEntry = listed.filter((e) => e.name === 'fxmanifest.lua')[0];
  const inside = maniEntry && maniEntry.data ? Buffer.from(maniEntry.data).toString('utf8') : '';
  check('sans cocher : manifeste nettoye a l interieur',
    inside.length > 0 && inside.indexOf('activate_ipl.lua') === -1 && inside.indexOf('client/other.lua') !== -1,
    inside.slice(0, 120));

  const rep = listed.filter((e) => e.name === 'CYPHERDECRYPTER.txt')[0];
  const repText = rep && rep.data ? Buffer.from(rep.data).toString('utf8') : '';
  check('rapport : faux echec de lecture retire', repText.indexOf('relancez-les seuls') === -1, repText.slice(0, 200));
  check('rapport : conteneurs annonces corriges',
    repText.indexOf('27 conteneur') === -1 && repText.indexOf('ESCROW-RETIRE.txt') !== -1,
    repText.slice(0, 200));
  check('rapport : mentionne le retrait du .fxap', repText.indexOf('.fxap de la ressource') !== -1, repText.slice(0, 200));

  check('mode sans escrow : .fxap reconnu comme a retirer', CE.isEscrowForRemoval({ path: 'tstudio_zmapdata/.fxap', bytes: new Uint8Array(8) }) === true);
  check('mode sans escrow : source lua non retiree', CE.isEscrowForRemoval({ path: 'client/x.lua', text: 'local a = 1\n' }) === false);
  check('rapport inchange hors escrow', CE.rewriteFxapReport('rien a corriger ici\n', { removed: 0 }) === 'rien a corriger ici\n');

  /* ---------------- desaccordement volontaire ---------------- */
  CE.set(false);
  const zOff = await ctx.Zip.entries(ctx.Zip.create([
    escrowEntry,
    { path: 'tstudio_zmapdata/.fxap', bytes: new Uint8Array(8) },
    { path: 'stream/a.ymap', bytes: encContainer }
  ], { comment: 'test' }));
  const offNames = zOff.map((e) => e.name);
  check('option desactivee : conteneur garde', offNames.indexOf('client/activate_ipl.lua') !== -1, offNames.join(', '));
  check('option desactivee : .fxap garde', offNames.indexOf('tstudio_zmapdata/.fxap') !== -1, offNames.join(', '));
  check('option desactivee : note informative ajoutee', offNames.indexOf('ESCROW-INFO.txt') !== -1, offNames.join(', '));

  const info = zOff.filter((e) => e.name === 'ESCROW-INFO.txt')[0];
  const infoText = info && info.data ? Buffer.from(info.data).toString('utf8') : '';
  check('note informative : nomme le fichier', infoText.indexOf('client/activate_ipl.lua') !== -1, infoText.slice(0, 120));

  const zPlain = ctx.Zip.create([{ path: 'client/x.lua', text: 'local a = 1\n' }], { comment: 'test' });
  const plainNames = (await ctx.Zip.entries(zPlain)).map((e) => e.name);
  check('archive sans conteneur : aucune note ajoutee',
    plainNames.indexOf('ESCROW-INFO.txt') === -1 && plainNames.indexOf('client/x.lua') !== -1,
    plainNames.join(', '));

  const app = fs.readFileSync(path.join(ROOT, 'js', 'app.js'), 'utf8');
  console.log('appels Lua54.parse( dans app.js : ' + (app.match(/Lua54\.parse\(/g) || []).length);

  console.log(fails ? fails + ' test(s) en echec' : 'tous les tests passent');
  process.exit(fails ? 1 : 0);
})().catch(function (e) {
  console.log('ERR  ' + (e && e.message ? e.message : e));
  console.log(String(e && e.stack || '').split('\n').slice(0, 6).join('\n'));
  process.exit(1);
});
