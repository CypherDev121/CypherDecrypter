# Changelog

Toutes les versions notables de CypherDecrypter.
Format [SemVer](https://semver.org/lang/fr/).

La version affichee sur le site est **injectee depuis le fichier `VERSION`** par le workflow de synchronisation : il suffit de modifier `VERSION` (et ce changelog) pour que le badge suive au prochain passage.

## [6.0.1] - 2026-11-09

### Corrige

- Decryptage des `.lua` de mappings : `js/app.js` appelait `Lua54.parse`, qui n'existe pas (seul `parseChunk` est exporte). L'appel levait une `TypeError` avalee par un `catch` vide, donc un `.lua` compile ou un bytecode compresse dans un conteneur FXAP n'etait jamais reconstruit : le fichier ressortait « non dechiffre ». Un alias est pose au chargement.
- AES-ECB : le mode dechiffrait bloc par bloc via AES-CBC, or WebCrypto retire le remplissage PKCS#7 de chaque bloc, ce qui detruit le clair et leve une erreur des que le remplissage est invalide. Le clair ECB est maintenant reconstruit sans perte (bloc de queue calcule), verifie contre l'implementation de reference de Node sur un vrai `.luac` 5.4.

### Ajoute

- `js/compat.js` : module de correctifs charge apres les autres et injecte dans `index.html` au deploiement Pages. Il vit hors des fichiers resynchronises, qui sont retelecharges a chaque passage.
- Workflow `verify-decrypt` : compile un chunk avec `luac5.4` puis verifie la lecture, la decompilation, AES-ECB et AES-CBC a chaque modification du moteur.

## [6.0.0] - 2026-11-09

### Ajoute

- Recuperation integrale des sources du site public : interface, 13 modules JavaScript et 4 logos, non minifies.
- Badge de version dans l'en-tete du site, alimente par le fichier `VERSION`.
- Workflow de synchronisation automatique (push, manuel, chaque nuit a 04:00 UTC) avec verification que chaque reference locale du HTML existe.

### Modifie

- Depot reorganise : `css/`, `js/`, `assets/brand/` au lieu de 18 fichiers a plat a la racine.
- `index.html` reecrit pour pointer vers la nouvelle arborescence.

### Note

Cette version marque la remise en etat du projet apres la perte du dossier local d'origine.
