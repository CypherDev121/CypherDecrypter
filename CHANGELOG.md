# Changelog

Toutes les versions notables de CypherDecrypter.
Format [SemVer](https://semver.org/lang/fr/).

La version affichee sur le site est **injectee depuis le fichier `VERSION`** par le workflow de synchronisation : il suffit de modifier `VERSION` (et ce changelog) pour que le badge suive au prochain passage.

## [6.1.1] - 2026-11-09

### Corrige

- Regression de la 6.1.0 : option d'export laissee decochee, l'archive etait ecrite a partir de la liste filtree, donc les conteneurs escrow disparaissaient alors que l'option etait desactivee. L'archive est maintenant ecrite a partir de la liste d'origine, conteneurs compris, avec la note `ESCROW-INFO.txt` en plus. Le test `option desactivee : conteneur garde` couvre ce cas.

## [6.1.0] - 2026-11-09

### Ajoute

- Option « Produire une archive sans aucun fichier escrow » dans l'onglet Clean FXAP & Mapping : les conteneurs chiffres sont retires de l'archive et chaque `fxmanifest.lua` est nettoye des references correspondantes, pour qu'aucun fichier manquant ne soit reclame au demarrage. Un rapport `ESCROW-RETIRE.txt` liste les fichiers ecartes et ce qui cesse de fonctionner.

### Corrige

- La detection d'un conteneur escrow ne depend plus de la forme de l'entree : un `.lua` peut arriver en octets bruts ou deja decode en chaine (latin-1 ou UTF-8 permissif). Les deux cas sont reconnus, un `fxmanifest` n'est jamais modifie par erreur, et les sources Lua accentuees ne sont jamais prises pour du chiffre.
- Le nettoyage du `fxmanifest` ne laisse plus de virgule orpheline quand le fichier retire occupait seul sa ligne : le manifeste produit est verifie par le vrai parseur `lua5.4`, pas par une expression reguliere.
- Le module de correctifs est charge apres `app.js` et rejoue au `DOMContentLoaded` : le correctif AES-ECB n'est plus ignore si `recover.js` n'est pas encore evalue au moment du chargement.

### Modifie

- Option laissee decochee : l'archive garde les conteneurs et ajoute `ESCROW-INFO.txt`, qui explique pourquoi un `.lua` chiffre s'affiche comme binaire (GitHub, editeur) et comment produire une archive sans escrow.
- Harnais de test deplace dans `tests/verify-decrypt.cjs`, execute par `node` : le journal du job reste court et lisible.

### Note

Cette option retire les fichiers escrow, elle ne les dechiffre pas. Un conteneur chiffre par FXAP reste indechiffrable sans la cle de l'auteur de la ressource.

## [6.0.1] - 2026-11-09

### Corrige

- Decryptage des `.lua` de mappings : `js/app.js` appelait `Lua54.parse`, qui n'existe pas (seul `parseChunk` est exporte). L'appel levait une `TypeError` avalee par un `catch` vide, donc un `.lua` compile ou un bytecode compresse dans un conteneur FXAP n'etait jamais reconstruit : le fichier ressortait « non dechiffre ». Un alias est pose au chargement.
- AES-ECB : le mode dechiffrait bloc par bloc via AES-CBC, or WebCrypto retire le remplissage PKCS#7 de chaque bloc, ce qui detruit le clair et leve une erreur des que le remplissage est invalide. Le clair ECB est maintenant reconstruit sans perte (bloc de queue calcule), verifie contre l'implementation de reference de Node sur un vrai `.luac` 5.4.

### Ajoute

- `js/compat.js` : module de correctifs charge apres les autres et injecte dans `index.html` au deploiement Pages. Il vit hors des fichiers resynchronises, qui sont retelescharges a chaque passage.
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
