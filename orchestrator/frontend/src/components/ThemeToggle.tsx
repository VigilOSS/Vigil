// Theme toggle button (Issue 2).
//
// Lives in both page headers (EngagementsPage + EngagementPage). Keeps a
// local copy of the active theme so the icon flips immediately, and
// subscribes to cross-tab storage events so multiple tabs stay in sync.

import { useEffect, useState } from "react";
import { getTheme, setTheme, subscribeTheme, type Theme } from "../lib/theme";

function IconMoon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
    </svg>
  );
}

function IconSun() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx={12} cy={12} r={4} />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  );
}

export function ThemeToggle() {
  const [theme, setLocalTheme] = useState<Theme>(() => getTheme());

  useEffect(() => subscribeTheme(setLocalTheme), []);

  const next: Theme = theme === "dark" ? "light" : "dark";
  const label = next === "dark" ? "Switch to dark mode" : "Switch to light mode";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={() => setTheme(next)}
      aria-label={label}
      title={label}
    >
      {theme === "dark" ? <IconSun /> : <IconMoon />}
      <span>{theme === "dark" ? "Light" : "Dark"}</span>
    </button>
  );
}
