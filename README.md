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
│   └── sync-site.yml     synchronisation + injection de la version
├── SYNC.txt              manifeste : source, version, references, tailles
└── README.md
```

## Version

Le fichier `VERSION` est la seule source de verite. Le workflow lit sa valeur et l'affiche dans l'en-tete du site (badge a cote de « Lua 5.4 »), puis commite avec `sync: site publie vX.Y.Z`.

Pour publier une nouvelle version :

1. modifier `VERSION` (`6.0.1`, `6.1.0`, `7.0.0` selon l'ampleur) ;
2. ajouter l'entree correspondante dans `CHANGELOG.md` ;
3. pousser — le badge et le manifeste suivent automatiquement.

## Lancer en local

Aucune dependance, aucun build : HTML/CSS/JS statique.

```bash
python -m http.server 8080
```

Puis ouvrir http://localhost:8080 .

## Synchronisation

Le workflow `sync-site.yml` tourne a chaque push sur `main`, a la demande, et chaque nuit a 04:00 UTC. Il retelecharge le site publie, le range dans cette arborescence, reecrit les chemins du HTML, injecte le badge de version, verifie que chaque reference existe, puis ne commite que si quelque chose a change.

## Notes

- Tout s'execute dans le navigateur : aucun fichier n'est envoye a un serveur.
- Depot prive. Un depot prive n'est pas open source : si le projet doit etre publie, il faut changer sa visibilite (Settings > General > Danger Zone).
