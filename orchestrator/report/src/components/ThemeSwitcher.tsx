import { Moon, Sun } from "lucide-react";
import { useTheme } from "../theme";

export function ThemeSwitcher() {
  const { theme, toggle } = useTheme();
  const isDark = theme === "dark";
  return (
    <button
      type="button"
      className="rpt-icon-btn no-print"
      onClick={toggle}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
    >
      {isDark ? <Sun size={14} /> : <Moon size={14} />}
      <span>{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}

export default ThemeSwitcher;
