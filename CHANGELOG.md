# Changelog

Toutes les versions notables de CypherDecrypter.
Format [SemVer](https://semver.org/lang/fr/).

La version affichee sur le site est **injectee depuis le fichier `VERSION`** par le workflow de synchronisation : il suffit de modifier `VERSION` (et ce changelog) pour que le badge suive au prochain passage.

## [6.0.0] - 2026-11-09

### Ajoute

- Recuperation integrale des sources du site publie : interface, 13 modules JavaScript et 4 logos, non minifies.
- Badge de version dans l'en-tete du site, alimente par le fichier `VERSION`.
- Workflow de synchronisation automatique (push, manuel, chaque nuit a 04:00 UTC) avec verification que chaque reference locale du HTML existe.

### Modifie

- Depot reorganise : `css/`, `js/`, `assets/brand/` au lieu de 18 fichiers a plat a la racine.
- `index.html` reecrit pour pointer vers la nouvelle arborescence.

### Note

Cette version marque la remise en etat du projet apres la perte du dossier local d'origine.
