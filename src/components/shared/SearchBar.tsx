import { createSignal, For, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useI18n } from "../../i18n/context";
import { search } from "../../utils/search-index";
import type { SearchResult } from "../../utils/search-index";
import "./SearchBar.css";

export default function SearchBar() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [query, setQuery] = createSignal("");
  const [results, setResults] = createSignal<SearchResult[]>([]);
  const [isOpen, setIsOpen] = createSignal(false);

  function handleInput(e: InputEvent) {
    const val = (e.target as HTMLInputElement).value;
    setQuery(val);
    if (val.trim().length >= 2) {
      setResults(search(val).slice(0, 8));
      setIsOpen(true);
    } else {
      setResults([]);
      setIsOpen(false);
    }
  }

  function handleSelect(result: SearchResult) {
    navigate(result.path);
    setQuery("");
    setResults([]);
    setIsOpen(false);
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      setIsOpen(false);
      (e.target as HTMLInputElement).blur();
    }
  }

  return (
    <div class="search-bar">
      <input
        type="text"
        class="search-input mono"
        placeholder={t("検索...", "Search...")}
        value={query()}
        onInput={handleInput}
        onKeyDown={handleKeyDown}
        onFocus={() => { if (results().length > 0) setIsOpen(true); }}
        onBlur={() => { setTimeout(() => setIsOpen(false), 200); }}
        aria-label={t("検索", "Search")}
      />
      <Show when={isOpen() && results().length > 0}>
        <div class="search-results">
          <For each={results()}>
            {(result) => (
              <button class="search-result-item" onClick={() => handleSelect(result)}>
                <span class="sr-view mono">{result.view}</span>
                <span class="sr-title">{t(result.titleJa, result.title)}</span>
                <span class="sr-desc">{t(result.descriptionJa, result.description)}</span>
              </button>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
