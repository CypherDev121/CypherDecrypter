# CypherDecrypter

**Version actuelle : 6.0.0** (voir [CHANGELOG.md](CHANGELOG.md))

Boite a outils Lua 5.4 pour FiveM : decompilation de bytecode, nettoyage FXAP, audit et nettoyage de NUI/Lua, recuperation de sources obfusquees, classement local.

**Site public : https://cypherdev121.github.io/CypherDecrypter/**

Sources recuperees le 9 novembre 2026 depuis le site publie, apres la perte du dossier local d'origine. Le site servait ses fichiers non minifies : c'est le code d'origine, commentaires inclus.

## Arborescence

```
CypherDecrypter/
├── index.html            interface : 9 onglets + ecran de connexion
├── VERSION               version affichee sur le site (source unique)
├── CHANGELOG.md          historique des versions
├── css/
│   └── styles.css        tout le style (44 Ko)
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
│   └── island.js         element isole de l'interface
├── assets/
│   └── brand/            logos de l'ecran de connexion
├── .github/workflows/
│   ├── pages.yml         publication sur GitHub Pages
│   └── sync-site.yml     synchronisation + version + release
├── SYNC.txt              manifeste : source, version, references, tailles
└── README.md
```

## Site en ligne

Le depot est **public** et publie automatiquement sur GitHub Pages a chaque push sur `main` :

**https://cypherdev121.github.io/CypherDecrypter/**

`.github/workflows/pages.yml` copie `index.html`, `js/`, `css/` et `assets/` dans un artefact, puis le deploie. Aucun build : les fichiers sont deja statiques, donc les chemins relatifs du HTML fonctionnent tels quels.

Consequence : une modification de `VERSION` poussee sur `main` suffit a mettre a jour la pastille du site public. Il n'y a plus de publication manuelle a faire.

## Version

Le fichier `VERSION` est la seule source de verite. Le workflow de synchronisation lit sa valeur, l'ecrit dans le badge de l'en-tete, puis commite et publie une release `vX.Y.Z` si elle n'existe pas.

Pour publier une nouvelle version :

1. modifier `VERSION` (`6.0.1`, `6.1.0`, `7.0.0` selon l'ampleur) ;
2. ajouter l'entree correspondante dans `CHANGELOG.md` ;
3. pousser — badge, commit, release et site public suivent automatiquement.

## Source Freebuff (synchronisation)

`sync-site.yml` aspire encore la version hebergee par Freebuff sur
`https://site-69d99fb9841c47e8bfd4dda067302ad1.freebuff.page/` pour la conserver dans ce depot.

Le workflow gere les deux cas du badge de version : si la page aspiree porte deja `data-site-version`, il **remplace son numero** depuis `VERSION` ; sinon il insere la pastille apres `<span class="badge badge-azure">Lua 5.4</span>`.

Si le projet Freebuff n'est plus mis a jour, cette synchronisation reste sans effet sur le site public : GitHub Pages publie le contenu du depot.

## Lancer en local

Aucune dependance, aucun build : HTML/CSS/JS statique.

```bash
python -m http.server 8080
```

Puis ouvrir http://localhost:8080 .

## Notes

- Tout s'execute dans le navigateur : aucun fichier n'est envoye a un serveur.
- Le depot est public : le code des modules est donc lisible et forkable par tout le monde.
