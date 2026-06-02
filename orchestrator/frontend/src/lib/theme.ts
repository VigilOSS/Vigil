// Theme system (Issue 2).
//
// Single source of truth: the `data-theme` attribute on <html>. All CSS in
// `app.css` is authored against theme variables declared at `:root` and
// overridden at `:root[data-theme="dark"]`, so setting this one attribute
// flips the entire UI.
//
// Storage key is intentionally namespaced with `vigil.` so multiple apps on
// the same origin don't collide.

export type Theme = "light" | "dark";

const STORAGE_KEY = "vigil.theme";

/** Read the saved theme, or fall back to OS preference. */
export function detectInitialTheme(): Theme {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // localStorage access can throw under Safari private mode or
    // cross-origin iframes. Fall through to the OS preference.
  }
  const mq =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;
  return mq?.matches ? "dark" : "light";
}

/** Apply a theme to the document root. Safe to call before render. */
export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
}

/** Persist a theme and apply it. */
export function setTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Persist is best-effort; the in-memory attribute is still applied.
  }
  applyTheme(theme);
  // Notify in-process listeners so React components re-render without a
  // storage event round-trip (storage events only fire cross-tab).
  window.dispatchEvent(new CustomEvent<Theme>("vigil:theme-change", { detail: theme }));
}

/** Read the current document theme. */
export function getTheme(): Theme {
  const attr = document.documentElement.getAttribute("data-theme");
  return attr === "dark" ? "dark" : "light";
}

/**
 * Subscribe to theme changes. Fires on both in-process updates (from
 * `setTheme`) and cross-tab updates (from the `storage` event).
 */
export function subscribeTheme(listener: (theme: Theme) => void): () => void {
  const onCustom = (e: Event) => {
    const detail = (e as CustomEvent<Theme>).detail;
    if (detail === "light" || detail === "dark") listener(detail);
  };
  const onStorage = (e: StorageEvent) => {
    if (e.key !== STORAGE_KEY) return;
    const v = e.newValue;
    if (v === "light" || v === "dark") {
      applyTheme(v);
      listener(v);
    }
  };
  window.addEventListener("vigil:theme-change", onCustom as EventListener);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener("vigil:theme-change", onCustom as EventListener);
    window.removeEventListener("storage", onStorage);
  };
}
