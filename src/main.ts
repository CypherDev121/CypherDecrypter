/* main.ts — point d'entrée Vite de CypherDecrypter.
 *
 * Charge le pont Tauri en premier, puis les modules cœur (globaux UMD),
 * puis le câblage de l'interface, puis les correctifs — dans le même
 * ordre que les anciennes balises <script> d'index.html.
 */

import './setup';

import '../js/lua54.js';
import '../js/decompile.js';
import '../js/fxap.js';
import '../js/deobf.js';
import '../js/recover.js';
import '../js/zip.js';
import '../js/anti.js';
import '../js/nui.js';
import '../js/sanitize.js';
import '../js/accounts.js';
import '../js/records.js';
import '../js/island.js';
import '../js/app.js';
import '../js/compat.js';
