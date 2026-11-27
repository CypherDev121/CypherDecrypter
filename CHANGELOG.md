# Changelog

Toutes les versions notables de CypherDecrypter.
Format [SemVer](https://semver.org/lang/fr/).

Le fichier `VERSION`, `package.json` et `src-tauri/tauri.conf.json` portent la meme version : il suffit de les aligner (et ce changelog) pour publier.

## [7.0.7] - 2026-11-27

### Ajoute

- **Retrait des fichiers `escrow_ignore`** : le bloc du fxmanifest est parse et les fichiers en clair qu'il liste sont retires de l'archive sans escrow, en plus des conteneurs chiffres et du `.fxap`. La directive est commentee dans le manifeste nettoye ; `fxmanifest.lua`/`__resource.lua` ne sont jamais retires.
- `ESCROW-RETIRE.txt` distingue desormais les conteneurs chiffres des fichiers en clair retires via `escrow_ignore`.
- Tests de bout en bout sur une structure de ressource complete (manifest + fichiers chiffres + fichiers ignores + assets).

## [7.0.6] - 2026-11-26

### Corrige

- **Decryptage FXAP fonctionnel avec la cle escrow** : le vrai layout du conteneur est maintenant utilise (IV 16 octets a `0x0a`, charge utile a `0x1a`) au lieu d'offsets generiques qui ne la testaient jamais.
- Le clair est valide en **source .lua texte** et plus seulement en signature `\x1bLua` : un .lua escrow decrypte vers sa source, qui etait rejetee meme avec la bonne cle.
- AES-CTR : le flux n'est plus tronque a un multiple de 16 octets (la queue du fichier etait perdue) ; variantes de compteur 128 bits et little-endian essayees.
- Le wrapper ECB de compat laisse passer les conteneurs FXAP vers la logique de layout.

### Ajoute

- Resultat « source » gere partout : formulaire de cle, lot `fxapChunks`, export `.lua`.
- Selecteur de mode « Auto » par defaut (essaie CTR-128, CTR-64, CBC, ECB) ; l'IV est lue automatiquement dans l'en-tete FXAP quand elle n'est pas fournie.
- Le rapport d'analyse FXAP detaille la structure du conteneur (version, offset de l'IV, offset de la charge utile).
- `AGENTS.md` a la racine : commandes de build/test et conventions pour les agents.
- Tests aller-retour FXAP dans `tests/verify-decrypt.cjs` (source + chunk + rejet de mauvaise cle).

## [7.0.0] - 2026-11-20

### Ajoute

- **Application de bureau Windows** via Tauri 2 : la boite a outils tourne dans une vraie fenetre native, installee par `CypherDecrypter_x64-setup.exe` (NSIS, installation par utilisateur, sans droits admin).
- **Mises a jour automatiques** : `tauri-plugin-updater` interroge les releases GitHub au lancement, propose la mise a jour avec barre de progression, installe en mode passif et relance l'app. Artefacts signes (cle minisign generee par `tauri signer generate`).
- **Enregistrement natif des exports** : les .lua et .zip produits passent par la boite de dialogue « Enregistrer sous » de Windows au lieu du telechargement navigateur (repli navigateur conserve pour la version web).
- Barre de titre personnalisee (reduire / agrandir / fermer) sur la fenetre sans bordures.
- Workflow `release.yml` : sur un tag `v*`, build Windows, signature des artefacts et publication de la release avec `latest.json` pour l'updater.

### Modifie

- Le frontend est desormais compile par **Vite + TypeScript** : `src/main.ts` charge les 13 modules `js/` dans l'ordre historique, `src/setup.ts` isole tout le code Tauri. Le site GitHub Pages (`pages.yml`) deploye le meme build `dist/`.
- Les assets `assets/` passent sous `public/` pour etre recopies tels quels dans le build.

### Supprime

- Workflow `sync-site.yml` et `SYNC.txt` : le depot est desormais la source de verite, plus de retelechargement nocturne depuis l'ancien site Freebuff.

## [6.2.0] - 2026-11-09

### Modifie

- Le retrait de l'escrow est desormais **automatique et actif par defaut** : aucun clic n'est necessaire. Chaque export de l'onglet Clean FXAP & Mapping retire les conteneurs chiffres et le `.fxap` de la ressource, nettoie les `fxmanifest.lua` et ajoute `ESCROW-RETIRE.txt`. Le rapport de l'archive annonce l'etat reel au lieu des conteneurs recopies.
- La case n'est plus une action a faire mais une sortie de secours : decochee volontairement, elle conserve les conteneurs (FiveM les dechiffre lui-meme) et ajoute `ESCROW-INFO.txt`. Le desaccordement est memorise dans le navigateur ; le defaut reste le retrait.

### Corrige

- Le `.fxap` (manifeste du conteneur escrow) n'est plus signale comme un fichier illisible a « relancer seul » : il est retire avec les conteneurs, puisque sans les scripts chiffres il ne sert plus a rien.
- Le rapport produit par `app.js` est reecrit quand il annonce encore « N conteneur(s) FXAP encore chiffre(s) sont recopies » alors que l'archive n'en contient plus.

### Note

Ce mode retire les fichiers escrow, il ne les dechiffre pas. Un conteneur chiffre par FXAP reste indechiffrable sans la cle de l'auteur de la ressource.

## [6.1.2] - 2026-11-09

### Corrige

- Le `.fxap` de la ressource est retire lui aussi en mode sans escrow, et n'est plus signale comme un echec de lecture.
- Le rapport de l'archive decrit l'etat reel de l'archive produite.

### Modifie

- Le choix de l'option etait memorise dans le navigateur.

## [6.1.1] - 2026-11-09

### Corrige

- Regression de la 6.1.0 : option laissee decochee, l'archive etait ecrite a partir de la liste filtree, donc les conteneurs escrow disparaissaient alors que l'option etait desactivee.

## [6.1.0] - 2026-11-09

### Ajoute

- Option d'export sans escrow dans l'onglet Clean FXAP & Mapping, avec nettoyage des `fxmanifest.lua` et rapport `ESCROW-RETIRE.txt`.

### Corrige

- Detection d'un conteneur escrow independante de la forme de l'entree (octets ou chaine), sans jamais toucher une source Lua accentuee.
- Plus de virgule orpheline dans le `fxmanifest` quand le fichier retire occupait seul sa ligne ; le manifeste est valide par `lua5.4`.
- Le module de correctifs est charge apres `app.js` et rejoue au `DOMContentLoaded`.

## [6.0.1] - 2026-11-09

### Corrige

- Decryptage des `.lua` de mappings : `js/app.js` appelait `Lua54.parse`, qui n'existe pas (seul `parseChunk` est exporte). Un alias est pose au chargement.
- AES-ECB reconstruit sans perte (bloc de queue calcule), verifie contre l'implementation de reference de Node sur un vrai `.luac` 5.4.

### Ajoute

- `js/compat.js` : module de correctifs charge apres les autres et injecte au deploiement Pages.
- Workflow `verify-decrypt` : compile un chunk avec `luac5.4` puis verifie lecture, decompilation, AES-ECB et AES-CBC.

## [6.0.0] - 2026-11-09

### Ajoute

- Recuperation integrale des sources du site public : interface, 13 modules JavaScript et 4 logos, non minifies.
- Badge de version dans l'en-tete du site, alimente par le fichier `VERSION`.
- Workflow de synchronisation automatique (push, manuel, chaque nuit a 04:00 UTC).

### Modifie

- Depot reorganise : `css/`, `js/`, `assets/brand/` au lieu de 18 fichiers a plat a la racine.
- `index.html` reecrit pour pointer vers la nouvelle arborescence.

### Note

Cette version marque la remise en etat du projet apres la perte du dossier local d'origine.
