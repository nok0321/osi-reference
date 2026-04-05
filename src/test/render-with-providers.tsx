import { render } from "@solidjs/testing-library";
import { Router, Route } from "@solidjs/router";
import { ThemeProvider } from "../theme/context";
import { I18nProvider } from "../i18n/context";
import type { JSX, ParentProps } from "solid-js";

function Providers(props: ParentProps) {
  return (
    <ThemeProvider>
      <I18nProvider>
        {props.children}
      </I18nProvider>
    </ThemeProvider>
  );
}

export function renderWithProviders(ui: () => JSX.Element) {
  return render(() => (
    <Router root={Providers}>
      <Route path="/" component={() => ui()} />
      <Route path="/*" component={() => ui()} />
    </Router>
  ));
}
