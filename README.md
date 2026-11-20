# CypherDecrypter

**Version actuelle : 7.0.0** (voir [CHANGELOG.md](CHANGELOG.md))

Boite a outils Lua 5.4 pour FiveM : decompilation de bytecode, nettoyage FXAP, audit et nettoyage de NUI/Lua, recuperation de sources obfusquees, classement local.

- **Application Windows** : installeur `CypherDecrypter_x64-setup.exe` sur les [releases GitHub](https://github.com/CypherDev121/CypherDecrypter/releases), avec mises a jour automatiques.
- **Site public : https://cypherdev121.github.io/CypherDecrypter/** — meme code, meme build, dans le navigateur.

## Arborescence

```
CypherDecrypter/
├── index.html            interface : 9 onglets + ecran de connexion (entree Vite)
├── VERSION               version affichee sur le site
├── CHANGELOG.md          historique des versions
├── package.json          scripts npm + dependances (Vite, Tauri)
├── vite.config.ts        build frontend (base relative : Tauri + Pages)
├── tsconfig.json
├── src/
│   ├── main.ts           point d'entree : charge les modules js/ dans l'ordre
│   ├── setup.ts          pont Tauri : export natif, auto-update, barre de titre
│   └── globals.d.ts      types des globaux des modules legacy
├── css/
│   └── styles.css        tout le style
├── js/
│   ├── app.js            cablage de l'interface, lots, exports ZIP
│   ├── lua54.js          lecture du bytecode Lua 5.4
│   ├── decompile.js      desassemblage et reconstruction du source
│   ├── recover.js        chunks, AES-CBC/CTR/ECB, conteneurs FXAP
│   ├── fxap.js           analyse des conteneurs FXAP
│   ├── anti.js           audit backdoor et nettoyage Lua
│   ├── nui.js            audit NUI (eval, iframes, cookies)
│   ├── sanitize.js       neutralisation des motifs dangereux
│   ├── deobf.js          desobfuscation de source Lua
│   ├── records.js        classement local des sessions
│   ├── accounts.js       comptes locaux (PBKDF2-SHA256)
│   ├── zip.js            ecriture des archives ZIP
│   ├── island.js         pastille animee de l'interface
│   └── compat.js         correctifs appliques apres les autres modules
├── public/assets/
│   └── brand/            logos de l'ecran de connexion
├── src-tauri/            application de bureau (Rust + tauri.conf.json)
│   ├── capabilities/     permissions accordees a la fenetre
│   └── icons/            icones generees par `tauri icon`
├── tests/
│   └── verify-decrypt.cjs verification lecture/decompilation/AES sous Node
└── .github/workflows/
    ├── pages.yml         build Vite + deploiement GitHub Pages
    ├── release.yml       build Windows, installateur signe, release
    └── verify-decrypt.yml tests de la chaine de decryptage
```

## Application de bureau

Prerequis : **Node.js 22+** et **Rust stable** (toolchain MSVC + Visual Studio Build Tools sous Windows).

```bash
npm install
npm run tauri dev        # lance l'app en mode developpement
npm run tauri:build      # compile : .exe + installateur NSIS dans src-tauri/target/release/bundle/
```

Le frontend est compile par Vite dans `dist/` avant chaque build Tauri. La fenetre est sans bordures : `src/setup.ts` injecte la barre de titre, le pont d'export de fichiers et la verification de mise a jour.

## Mises a jour automatiques

`tauri-plugin-updater` interroge au lancement :

```
https://github.com/CypherDev121/CypherDecrypter/releases/latest/download/latest.json
```

`latest.json` et l'installateur signe sont produits par `release.yml` a chaque tag `v*`. La signature exige deux secrets de depot :

| Secret | Contenu |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | contenu de `%USERPROFILE%\.tauri\cypherdecrypter.key` |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | contenu de `%USERPROFILE%\.tauri\cypherdecrypter.key.password` |

Sans ces secrets la release est publiee non signee et l'updater la rejete. La cle privee ne doit jamais etre committee : seuls ces secrets la connaissent.

## Publier une version

1. Aligner `VERSION`, `package.json › version`, `src-tauri/tauri.conf.json › version` et `Cargo.toml › version` ;
2. ajouter l'entree dans `CHANGELOG.md` ;
3. `git tag vX.Y.Z && git push --tags` — `release.yml` construit et publie une release en **brouillon** ;
4. verifier la release puis la publier : l'updater des clients installes la voit aussitot.

## Site en ligne

`pages.yml` compile le frontend (`npm ci && npm run build`) puis deploie `dist/` sur GitHub Pages. Le badge de version du site est aligne sur `VERSION` au deploiement.

## Lancer le frontend seul

```bash
npm install
npm run dev            # http://localhost:5173 (build Vite, modules bundles)
```

ou sans build, comme historiquement :

```bash
python -m http.server 8080   # servir la racine : js/ et css/ restent statiques
```

(attention : `index.html` charge desormais `/src/main.ts` — le mode sans build exige `npm run dev`, le serveur statique simple ne transpile pas le TypeScript.)

## Notes

- Tout s'execute en local : aucun fichier n'est envoye a un serveur, que ce soit dans le navigateur ou dans l'app.
- Le depot est public : le code des modules est donc lisible et forkable par tout le monde.
