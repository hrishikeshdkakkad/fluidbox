export type Theme = "dark" | "light";

export const THEME_STORAGE_KEY = "fluidbox-color-theme";
export const THEME_EVENT = "fluidbox:theme-change";

export function resolveTheme(stored: string | null, prefersDark: boolean): Theme {
  if (stored === "dark" || stored === "light") return stored;
  return prefersDark ? "dark" : "light";
}

/**
 * Runs while the document is still being parsed, before the first paint.
 * Keep this dependency-free: it is emitted directly into the root <head>.
 */
export const THEME_INIT_SCRIPT = `(()=>{try{const k=${JSON.stringify(
  THEME_STORAGE_KEY
)};const s=localStorage.getItem(k);const t=s==="dark"||s==="light"?s:(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light");const d=document.documentElement;d.dataset.theme=t;d.style.colorScheme=t}catch{}})()`;
