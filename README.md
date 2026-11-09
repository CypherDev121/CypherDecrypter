# CypherDecrypter

Depot **prive** de sauvegarde et de reprise du projet **CypherDecrypter** (site de dechiffrement).

Le code d'origine se trouvait sur le PC local, dans `C:\Users\CypherDev\Documents\CypherDecrypter`. Ce PC a ete reinitialise : le dossier est perdu tel quel. Ce depot sert de point de reprise et doit contenir la version reconstituee du projet, puis historiser toutes les evolutions.

> Le depot est prive. Un depot prive n'est pas open source : si l'objectif est de publier le projet, il faudra passer la visibilite en public (Settings > General > Danger Zone > Change visibility).

## Statut de la recuperation

- [ ] Identifier ce qui a survecu (OneDrive, hebergeur, archive locale)
- [ ] Reconstituer l'arborescence du projet
- [ ] Reintegrer les fonctions de dechiffrement
- [ ] Verifier que le site fonctionne a nouveau en local
- [ ] Deployer

## Pistes de recuperation

1. **OneDrive** : `Documents` est souvent synchronise. Verifier la corbeille OneDrive et l'historique des versions du dossier sur onedrive.live.com.
2. **Hebergeur** (Vercel, Netlify, Cloudflare Pages, VPS) : le compte survit a la reinitialisation du PC. Les deploiements restent accessibles et peuvent etre telecharges (code minifie, mais exploitable en partie).
3. **Wayback Machine** : si le site etait en ligne, les bundles JS archives permettent parfois de recuperer des fichiers perdus.
4. **Sauvegardes disque** : `Windows.old`, disque externe, File History, Dropbox/Google Drive.

Attention : un site deploye sert du JavaScript minifie. Les noms de fonctions et de variables d'origine ne s'y trouvent pas, sauf si des fichiers `.map` (source maps) sont restes accessibles.

## Structure cible

```
CypherDecrypter/
  README.md
  .gitignore
  (a completer avec l'arborescence reconstituee)
```

## Mise en place locale

```bash
git clone https://github.com/CypherDev121/CypherDecrypter.git
cd CypherDecrypter
```
