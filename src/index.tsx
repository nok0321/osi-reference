/* @refresh reload */
import { render } from "solid-js/web";
import { I18nProvider } from "./i18n/context";
import App from "./App";

const root = document.getElementById("root");

render(
  () => (
    <I18nProvider>
      <App />
    </I18nProvider>
  ),
  root!
);
