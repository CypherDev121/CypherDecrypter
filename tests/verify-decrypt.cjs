/* Verification automatique du decryptage et de l'export.

   Execute par .github/workflows/verify-decrypt.yml : `node tests/verify-decrypt.cjs`.
   Aucun navigateur : les modules sont charges dans un contexte vm, comme le
   serait le site, et le chunk de reference est compile par luac5.4.

   Sortie : une ligne par verification, puis un bilan. Code 0 si tout passe. */
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

  /* ---------------- lecture du bytecode ---------------- */
  check('Lua54.parseChunk est expose', typeof L.parseChunk === 'function');
  check('Lua54.parse est expose (correctif)', typeof L.parse === 'function');
  check('Recover.decrypt est expose', typeof R.decrypt === 'function');

  const bytes = new Uint8Array(fs.readFileSync(LUAC));

  let viaParse = null;
  try { viaParse = L.parse(bytes); } catch (e) { console.log('err parse: ' + e.message); }
  check('Lua54.parse lit un vrai .luac', !!(viaParse && viaParse.main));

  let code = '';
  if (viaParse && viaParse.main) {
    try { code = L.decompile(viaParse.main, { fileName: 'a.luac' }).code; } catch (e) { console.log('err decompile: ' + e.message); }
  }
  check('decompilation produite', code.length > 20, code.slice(0, 60));

  /* ---------------- AES-ECB / AES-CBC ---------------- */
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

  /* ---------------- export sans escrow ---------------- */
  check('filtre escrow expose', !!(CE && typeof CE.isEscrowEntry === 'function'));
  if (!CE) throw new Error('CypherEscrow absent : compat.js n a pas termine son evaluation');

  const encContainer = new Uint8Array(Buffer.concat([
    Buffer.from('FXAP'), nodeCrypto.randomBytes(400)
  ]));
  const escrowEntry = { path: 'client/activate_ipl.lua', bytes: encContainer };

  check('conteneur chiffre reconnu', CE.isEscrowEntry(escrowEntry) === true);
  check('source .lua conservee', CE.isEscrowEntry({ path: 'client/x.lua', bytes: new Uint8Array(Buffer.from('local a = 1\nprint(a)\n')) }) === false);
  check('bytecode conserve', CE.isEscrowEntry({ path: 'client/y.lua', bytes }) === false);
  check('asset .ymap non touche', CE.isEscrowEntry({ path: 'stream/a.ymap', bytes: encContainer }) === false);

  const mani = "fx_version 'cerulean'\nclient_scripts {\n  'client/activate_ipl.lua',\n  'client/other.lua'\n}\nclient_script 'client/Elevator.lua'\n";
  const maniOut = CE.stripManifest(mani, ['client/activate_ipl.lua', 'client/Elevator.lua'], 2);
  check('manifeste : reference retiree', maniOut.indexOf('activate_ipl.lua') === -1, maniOut);
  check('manifeste : directive orpheline commentee', maniOut.indexOf("client_script 'client/Elevator.lua'") === -1 && /-- retire/.test(maniOut), maniOut);
  check('manifeste : entree voisine gardee', maniOut.indexOf('client/other.lua') !== -1, maniOut);
  check('manifeste : pas de virgule orpheline', !/\{\s*,/.test(maniOut) && !/\n\s*,/.test(maniOut), maniOut);

  // La syntaxe est verifiee par le vrai parseur Lua, pas par une expression reguliere.
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

  /* ---------------- archive ---------------- */
  if (typeof ctx.Zip.create !== 'function') throw new Error('Zip.create absent');

  CE.set(true);
  const zOn = ctx.Zip.create([
    escrowEntry,
    { path: 'stream/a.ymap', bytes: encContainer },
    { path: 'fxmanifest.lua', text: mani }
  ], { comment: 'test' });
  check('zip sans escrow : Zip.create renvoie des octets', zOn instanceof Uint8Array && zOn.length > 0, zOn && zOn.constructor && zOn.constructor.name);
  const onBytes = Buffer.from(zOn);
  check('zip sans escrow : conteneur absent', onBytes.indexOf(Buffer.from('activate_ipl.lua')) === -1);
  check('zip sans escrow : asset present', onBytes.indexOf(Buffer.from('stream/a.ymap')) !== -1);
  check('zip sans escrow : rapport present', onBytes.indexOf(Buffer.from('ESCROW-RETIRE.txt')) !== -1);
  check('zip sans escrow : manifeste present', onBytes.indexOf(Buffer.from('fxmanifest.lua')) !== -1);

  CE.set(false);
  const zOff = Buffer.from(ctx.Zip.create([escrowEntry], { comment: 'test' }));
  check('option desactivee : conteneur garde', zOff.indexOf(Buffer.from('activate_ipl.lua')) !== -1);

  const app = fs.readFileSync(path.join(ROOT, 'js', 'app.js'), 'utf8');
  console.log('appels Lua54.parse( dans app.js : ' + (app.match(/Lua54\.parse\(/g) || []).length);

  console.log(fails ? fails + ' test(s) en echec' : 'tous les tests passent');
  process.exit(fails ? 1 : 0);
})().catch(function (e) {
  console.log('ERR  ' + (e && e.message ? e.message : e));
  console.log(String(e && e.stack || '').split('\n').slice(0, 6).join('\n'));
  process.exit(1);
});
