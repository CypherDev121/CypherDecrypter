# CypherDecrypter — Notes pour agents

Boite a outils Lua 5.4 pour FiveM : decompilation de bytecode, nettoyage FXAP,
audit NUI/Lua, deobfuscation. Meme code publie en deux formes :

- **App de bureau** : Tauri 2 (Rust + WebView), installeur NSIS sur les releases.
- **Site statique** : GitHub Pages (`https://cypherdev121.github.io/CypherDecrypter/`),
  build Vite de `src/main.ts` qui embarque les modules `js/`.

## Prerequis

- Node.js 22+ (le workflow Pages tourne en Node 22 ; verify-decrypt en Node 20)
- Rust stable + toolchain MSVC + Visual Studio Build Tools (build Tauri uniquement)
- `lua5.4` / `luac5.4` pour la suite de tests de decryptage

## Commandes

```bash
npm install          # ou npm ci en CI
npm run dev          # serveur Vite de dev (site)
npm run build        # build Vite -> dist/ (base relative : Tauri + Pages)
npm run tauri dev    # app de bureau en mode dev
npm run tauri build  # installeur Windows NSIS
```

## Tests

```bash
# Generer un chunk de reference puis lancer le harnais Node :
printf 'local n = 0\nfor i = 1, 3 do n = n + i end\nprint("hi", n)\n' > /tmp/a.lua
luac5.4 -o /tmp/a.luac /tmp/a.lua
node tests/verify-decrypt.cjs          # ou LUAC_PATH=<chemin.luac> node tests/verify-decrypt.cjs
```

`tests/verify-decrypt.cjs` charge `js/lua54.js`, `decompile.js`, `recover.js`,
`zip.js`, `compat.js` dans un contexte `vm` (pas de navigateur) : verifie la
lecture/decompilation d'un `.luac` 5.4 reel, AES-ECB (clair exact), AES-CBC
(intact) et le filtre d'export sans escrow.

## Versioning / releases

- `VERSION` : version affichee sur le site (la pastille est realignee dans le
  workflow Pages). `package.json` + `CHANGELOG.md` suivent la meme version.
- Commits de release : `release: X.Y.Z` (voir `git log`).
- `.github/workflows/release.yml` : build Windows + installeur signe + release.
- `.github/workflows/pages.yml` : deploye `dist/` sur Pages a chaque push `main`.

## Architecture

- `index.html` : interface (9 onglets + ecran de connexion), point d'entree Vite.
- `src/main.ts` : charge les modules `js/` dans l'ordre ; `src/setup.ts` = pont
  Tauri (export natif, auto-update, barre de titre) ; `src/globals.d.ts` = types.
- `js/` : modules legacy en JS global (`app.js`, `lua54.js`, `decompile.js`,
  `recover.js`, `fxap.js`, `anti.js`, `nui.js`, `sanitize.js`, `deobf.js`,
  `records.js`, `accounts.js`, `zip.js`, `island.js`, `compat.js` — ce dernier
  s'applique apres les autres).
- `src-tauri/` : conf Tauri, `capabilities/` (permissions fenetre), `icons/`.

## Conventions

- Code, commentaires, README et CHANGELOG en francais.
- Messages de commit : conventional commits (`feat:`, `fix:`, `ui:`,
  `release:`...), francais ou anglais, minuscules apres le type.
- Les requetes reseau dans l'app passent par `tauri-plugin-http`
  (CORS WebView) — pas de `fetch` direct cote Tauri.
