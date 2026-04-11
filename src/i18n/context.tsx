import { createSignal, createContext, useContext, type ParentProps, type Accessor } from "solid-js";

type Lang = "ja" | "en";

interface I18nContextValue {
  lang: Accessor<Lang>;
  setLang: (lang: Lang) => void;
  toggle: () => void;
  t: {
    (ja: string, en: string): string;
    (ja: string[], en: string[]): string[];
  };
}

const I18nContext = createContext<I18nContextValue>();

export function I18nProvider(props: ParentProps) {
  const [lang, setLang] = createSignal<Lang>("ja");

  const toggle = () => setLang(prev => (prev === "ja" ? "en" : "ja"));
  function t(ja: string, en: string): string;
  function t(ja: string[], en: string[]): string[];
  function t(ja: string | string[], en: string | string[]) {
    return lang() === "ja" ? ja : en;
  }

  return (
    <I18nContext.Provider value={{ lang, setLang, toggle, t }}>
      {props.children}
    </I18nContext.Provider>
  );
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
