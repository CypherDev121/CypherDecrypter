# CypherDecrypter

Boite a outils Lua 5.4 pour FiveM : decompilation de bytecode, nettoyage FXAP, audit et nettoyage de NUI/Lua, recuperation de sources obfusquees, classement local.

**Sources recuperees le 9 novembre 2026** depuis le site publie, apres la perte du dossier local d'origine. Le site servait ses fichiers source non minifies : le contenu recupere est le code d'origine, commentaires inclus, pas un bundle reconstitue.

## Contenu

| Fichier | Role |
| --- | --- |
| `index.html` | Structure de l'interface (onglets Bytecode, FXAP, Classement, Source, Recuperation, AntiBackdoor, AntiCleanLUA, AntiCleanNUI, AntiCleanBackdoor) |
| `styles.css` | Styles complets |
| `app.js` | Cablage de l'interface, traitements par lot, exports |
| `lua54.js` | Lecture du bytecode Lua 5.4 (en-tete, constantes, prototypes) |
| `decompile.js` | Desassemblage et reconstruction du source Lua |
| `recover.js` | Extraction de chunks, AES-CBC/CTR/ECB avec cle, nettoyage des conteneurs FXAP |
| `fxap.js` | Analyse des conteneurs FXAP (entropie, verdict, chaines) |
| `nui.js` | Audit NUI (eval, scripts distants, iframes, cookies, @import) |
| `anti.js` | Audit backdoor Lua et nettoyage (renommage `L_xx`, lignes mortes) |
| `sanitize.js` | Neutralisation des motifs dangereux en commentaire |
| `deobf.js` | Desobfuscation de source Lua |
| `records.js` | Classement local des sessions |
| `accounts.js` | Comptes locaux (PBKDF2-SHA256, code de recuperation `CD-XXXX-XXXX-XXXX`) |
| `zip.js` | Ecriture des archives ZIP |
| `island.js` | Element isole de l'interface |
| `brand/*.svg` | Logos affiches dans l'ecran de connexion |

Total : environ 350 Ko de source.

## Lancer en local

Aucune dependance, aucun build : c'est du HTML/CSS/JS statique.

```bash
python -m http.server 8080
```

Puis ouvrir http://localhost:8080 .

## Recuperation

Les fichiers ont ete telecharges par `.github/workflows/recover-sources.yml`, qui suit les balises `src` et `href` de `index.html` puis complete avec les modules connus. Relancer ce workflow resynchronise le depot avec la version publiee tant qu'elle est en ligne.

## Notes

- Tout s'execute dans le navigateur : aucun fichier n'est envoye a un serveur.
- Depot prive. Un depot prive n'est pas open source : si le projet doit etre publie, il faudra changer sa visibilite (Settings > General > Danger Zone).
