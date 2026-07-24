"use client";

import { useEffect, useState } from "react";
import {
  resolveTheme,
  THEME_EVENT,
  THEME_STORAGE_KEY,
  Theme,
} from "../lib/theme";

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function syncBrowserChrome(theme: Theme) {
  document
    .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "dark" ? "#111318" : "#f4f2ed");
}

function applyTheme(theme: Theme, persist: boolean) {
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  if (persist) localStorage.setItem(THEME_STORAGE_KEY, theme);
  syncBrowserChrome(theme);
  window.dispatchEvent(new CustomEvent<Theme>(THEME_EVENT, { detail: theme }));
}

export function ThemeToggle() {
  // The server and hydration pass both start dark; the no-flash head script has
  // already painted the correct theme, and this state catches up immediately.
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const sync = () => {
      const current = currentTheme();
      setTheme(current);
      syncBrowserChrome(current);
    };
    const followSystem = () => {
      if (localStorage.getItem(THEME_STORAGE_KEY) == null) {
        applyTheme(resolveTheme(null, media.matches), false);
      }
    };
    const syncFromStorage = (event: StorageEvent) => {
      if (event.key !== THEME_STORAGE_KEY) return;
      applyTheme(resolveTheme(event.newValue, media.matches), false);
    };

    sync();
    window.addEventListener(THEME_EVENT, sync);
    window.addEventListener("storage", syncFromStorage);
    media.addEventListener("change", followSystem);
    return () => {
      window.removeEventListener(THEME_EVENT, sync);
      window.removeEventListener("storage", syncFromStorage);
      media.removeEventListener("change", followSystem);
    };
  }, []);

  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      className="theme-toggle"
      type="button"
      aria-label={`Use ${next} theme`}
      title={`Use ${next} theme`}
      onClick={() => applyTheme(next, true)}
    >
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
      <span>{theme === "dark" ? "Light" : "Dark"}</span>
    </button>
  );
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 2.5v2M12 19.5v2M4.5 12h-2M21.5 12h-2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 15.1A8.2 8.2 0 0 1 8.9 4a8.3 8.3 0 1 0 11.1 11.1Z" />
    </svg>
  );
}
