# CypherDecrypter

**Version actuelle : 6.0.0** (voir [CHANGELOG.md](CHANGELOG.md))

Boite a outils Lua 5.4 pour FiveM : decompilation de bytecode, nettoyage FXAP, audit et nettoyage de NUI/Lua, recuperation de sources obfusquees, classement local.

**Sources recuperees le 9 novembre 2026** depuis le site publie, apres la perte du dossier local d'origine. Le site servait ses fichiers non minifies : c'est le code d'origine, commentaires inclus.

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
│   └── sync-site.yml     synchronisation + version + release
├── SYNC.txt              manifeste : source, version, references, tailles
└── README.md
```

## Version

Le fichier `VERSION` est la seule source de verite. Le workflow lit sa valeur, l'ecrit dans le badge de l'en-tete, puis commite et publie une release `vX.Y.Z` si elle n'existe pas.

Pour publier une nouvelle version :

1. modifier `VERSION` (`6.0.1`, `6.1.0`, `7.0.0` selon l'ampleur) ;
2. ajouter l'entree correspondante dans `CHANGELOG.md` ;
3. pousser — badge, commit et release suivent automatiquement.

## Publication du site

Le site public est heberge par **Freebuff** (projet « CypherDecrypter — Lua 5.4 ») sur
`https://site-69d99fb9841c47e8bfd4dda067302ad1.freebuff.page/`.

La publication se declenche depuis l'application Freebuff : le depot GitHub ne peut pas la lancer.
Pour que la version soit visible par les visiteurs, la page publiee doit contenir cette pastille,
juste apres `<span class="badge badge-azure">Lua 5.4</span>` dans l'en-tete :

```html
<span class="badge badge-azure" data-site-version="v6.0.0" title="Version du site">v6.0.0</span>
```

Le workflow gere les deux cas : si la page publiee porte deja la pastille, il **met a jour son
numero** depuis `VERSION` ; sinon il l'insere. Une montee de version se propage donc meme si le
HTML publie contient deja un numero.

## Lancer en local

Aucune dependance, aucun build : HTML/CSS/JS statique.

```bash
python -m http.server 8080
```

Puis ouvrir http://localhost:8080 .

## Notes

- Tout s'execute dans le navigateur : aucun fichier n'est envoye a un serveur.
- Depot prive. Un depot prive n'est pas open source : si le projet doit etre publie, il faut changer sa visibilite (Settings > General > Danger Zone).
