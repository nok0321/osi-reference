import { createSignal, createEffect, createContext, useContext, type ParentProps, type Accessor } from "solid-js";

type Theme = "dark" | "light";

interface ThemeContextValue {
  theme: Accessor<Theme>;
  setTheme: (theme: Theme) => void;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue>();

function getInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem("osi-theme");
    if (stored === "light" || stored === "dark") return stored;
  } catch {}
  return "dark";
}

export function ThemeProvider(props: ParentProps) {
  const [theme, setTheme] = createSignal<Theme>(getInitialTheme());

  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  createEffect(() => {
    const t = theme();
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("osi-theme", t); } catch {}
  });

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle }}>
      {props.children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
