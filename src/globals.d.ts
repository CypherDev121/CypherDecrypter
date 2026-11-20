/* Déclarations des globaux exposés par les modules legacy js/. */

declare const Lua54: any;
declare const Fxap: any;
declare const Recover: any;
declare const Deobf: any;
declare const Zip: any;
declare const Anti: any;
declare const Nui: any;
declare const Sanitize: any;
declare const Records: any;
declare const Accounts: any;
declare const Island: any;
declare const Compat: any;

interface Window {
  Lua54?: any;
  Fxap?: any;
  Recover?: any;
  Deobf?: any;
  Zip?: any;
  Anti?: any;
  Nui?: any;
  Sanitize?: any;
  Records?: any;
  Accounts?: any;
  Island?: any;
  Compat?: any;
  __TAURI_INTERNALS__?: unknown;
  CypherBridge?: {
    isTauri: boolean;
    save: (name: string, data: Blob | Uint8Array | string) => Promise<void>;
  };
}
