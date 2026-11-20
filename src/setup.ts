/* setup.ts — pont entre l'interface web et l'application de bureau Tauri.
 *
 * - CypherBridge.save() : export de fichiers via la boîte de dialogue native
 *   (dans le navigateur, repli sur le téléchargement blob classique).
 * - Vérification des mises à jour au lancement (tauri-plugin-updater).
 * - Barre de titre personnalisée quand la fenêtre est sans décorations.
 *
 * Ce module est importé en premier par main.ts, avant app.js.
 */

import { save } from '@tauri-apps/plugin-dialog';
import { writeFile } from '@tauri-apps/plugin-fs';
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

export const isTauri =
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

/* ------------------------------------------------------------------ *
 *  Export de fichiers
 * ------------------------------------------------------------------ */

function fallbackDownload(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

async function saveBlob(name: string, data: Blob | Uint8Array | string): Promise<void> {
  const blob =
    data instanceof Blob
      ? data
      : new Blob(
          [typeof data === 'string' ? new TextEncoder().encode(data) : (data as Uint8Array<ArrayBuffer>)],
          { type: 'application/octet-stream' },
        );

  if (!isTauri) {
    fallbackDownload(name, blob);
    return;
  }

  try {
    const path = await save({ defaultPath: name });
    if (!path) return; // boîte de dialogue annulée
    const bytes = new Uint8Array(await blob.arrayBuffer());
    await writeFile(path, bytes);
    window.Island?.notify?.('Export enregistré', path);
  } catch (err) {
    console.error('Sauvegarde impossible :', err);
    window.alert?.("Enregistrement du fichier impossible : " + (err as Error).message);
  }
}

/* ------------------------------------------------------------------ *
 *  Mises à jour
 * ------------------------------------------------------------------ */

const UPDATE_STYLE = `
.update-toast{position:fixed;right:18px;bottom:18px;z-index:9999;display:flex;flex-direction:column;gap:8px;
  max-width:340px;padding:14px 16px;border-radius:14px;background:rgba(17,24,32,.92);
  border:1px solid rgba(255,255,255,.13);backdrop-filter:blur(14px);color:#e2e8f0;
  font:14px/1.5 "Segoe UI",sans-serif;box-shadow:0 18px 50px rgba(0,0,0,.45)}
.update-toast b{color:#ff7f50}
.update-toast .u-actions{display:flex;gap:8px}
.update-toast button{flex:1;padding:7px 12px;border-radius:9px;border:1px solid rgba(255,255,255,.13);
  background:transparent;color:#e2e8f0;cursor:pointer;font:inherit}
.update-toast button.primary{background:#ff7f50;border-color:#ff7f50;color:#0b0f14;font-weight:600}
.update-toast .u-bar{height:4px;border-radius:2px;background:rgba(255,255,255,.1);overflow:hidden}
.update-toast .u-fill{height:100%;width:0;background:#ff7f50;transition:width .2s}
`;

async function runUpdate(update: Update, toast: HTMLElement): Promise<void> {
  const fill = toast.querySelector<HTMLElement>('.u-fill');
  const label = toast.querySelector<HTMLElement>('.u-label');
  let downloaded = 0;
  let total = 0;
  await update.downloadAndInstall((ev) => {
    if (ev.event === 'Started' && ev.data.contentLength) total = ev.data.contentLength;
    else if (ev.event === 'Progress') downloaded += ev.data.chunkLength;
    else if (ev.event === 'Finished' && label) label.textContent = 'Installation…';
    if (fill && total) fill.style.width = `${Math.min(100, (downloaded / total) * 100)}%`;
  });
  await relaunch();
}

function showToast(html: string, autoRemoveMs = 0): HTMLElement {
  if (!document.querySelector('style[data-update-style]')) {
    const style = document.createElement('style');
    style.setAttribute('data-update-style', '');
    style.textContent = UPDATE_STYLE;
    document.head.appendChild(style);
  }
  const toast = document.createElement('div');
  toast.className = 'update-toast';
  toast.innerHTML = html;
  document.body.appendChild(toast);
  if (autoRemoveMs > 0) setTimeout(() => toast.remove(), autoRemoveMs);
  return toast;
}

async function checkForUpdates(manual = false): Promise<void> {
  let checking: HTMLElement | null = null;
  try {
    if (manual) checking = showToast('<div class="u-label">Vérification des mises à jour…</div>');
    const update = await check();
    checking?.remove();
    if (!update) {
      if (manual) showToast('<div class="u-label">✅ Application à jour.</div>', 4000);
      return;
    }

    const toast = showToast(
      `<div class="u-label">Mise à jour <b>v${update.version}</b> disponible` +
      ` (installée : v${update.currentVersion})</div>` +
      `<div class="u-bar"><div class="u-fill"></div></div>` +
      `<div class="u-actions"><button class="primary" type="button">Mettre à jour</button>` +
      `<button type="button">Plus tard</button></div>`);

    const [btnYes, btnNo] = Array.from(toast.querySelectorAll('button'));
    btnNo.addEventListener('click', () => toast.remove());
    btnYes.addEventListener('click', async () => {
      btnYes.setAttribute('disabled', '');
      btnNo.setAttribute('disabled', '');
      try {
        await runUpdate(update, toast);
      } catch (err) {
        const label = toast.querySelector('.u-label');
        if (label) label.textContent = 'Échec de la mise à jour : ' + (err as Error).message;
        btnYes.removeAttribute('disabled');
        btnNo.removeAttribute('disabled');
      }
    });
  } catch (err) {
    console.warn('Vérification des mises à jour :', err);
  }
}

/* ------------------------------------------------------------------ *
 *  Barre de titre personnalisée (fenêtre sans décorations)
 * ------------------------------------------------------------------ */

async function setupTitlebar(): Promise<void> {
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  const appWindow = getCurrentWindow();

  const bar = document.createElement('div');
  bar.className = 'titlebar';
  bar.setAttribute('data-tauri-drag-region', '');
  bar.innerHTML =
    `<span class="titlebar-brand" data-tauri-drag-region>{} CypherDecrypter</span>` +
    `<div class="titlebar-btns">` +
    `<button class="tb-btn" id="tb-min" title="Réduire">–</button>` +
    `<button class="tb-btn" id="tb-max" title="Agrandir">□</button>` +
    `<button class="tb-btn tb-close" id="tb-close" title="Fermer">×</button>` +
    `</div>`;
  document.body.prepend(bar);

  bar.querySelector('#tb-min')?.addEventListener('click', () => appWindow.minimize());
  bar.querySelector('#tb-max')?.addEventListener('click', () => appWindow.toggleMaximize());
  bar.querySelector('#tb-close')?.addEventListener('click', () => appWindow.close());
}

/* ------------------------------------------------------------------ */

window.CypherBridge = { isTauri, save: saveBlob };

if (isTauri) {
  (window as any).checkForUpdates = checkForUpdates;

document.addEventListener('DOMContentLoaded', async () => {
  // Badge = version réellement installée (synchro, pas de F5 nécessaire).
  try {
    const { getVersion } = await import('@tauri-apps/api/app');
    const v = await getVersion();
    document.querySelectorAll<HTMLElement>('[data-site-version]').forEach((el) => {
      el.textContent = 'v' + v;
      el.setAttribute('data-site-version', 'v' + v);
    });
  } catch { /* navigateur : garder le badge du site */ }
    setupTitlebar().catch((e) => console.warn('titlebar:', e));
    checkForUpdates().catch((e) => console.warn('updater:', e));
  });
}
