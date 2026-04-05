/* @refresh reload */
import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import { ThemeProvider } from "./theme/context";
import { I18nProvider } from "./i18n/context";
import App from "./App";
import type { ParentProps } from "solid-js";

function Providers(props: ParentProps) {
  return (
    <ThemeProvider>
      <I18nProvider>
        {props.children}
      </I18nProvider>
    </ThemeProvider>
  );
}

const root = document.getElementById("root");

render(
  () => (
    <Router root={Providers}>
      <Route path="/*" component={App} />
    </Router>
  ),
  root!
);
