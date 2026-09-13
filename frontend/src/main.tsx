import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { polyfillCountryFlagEmojis } from "country-flag-emoji-polyfill";
import flagFontUrl from "country-flag-emoji-polyfill/dist/TwemojiCountryFlags.woff2?url";
import { App } from "./App";
import "./index.css";

// Windows Chromium ships no country-flag glyphs and renders them as letters.
// The bundled Twemoji subset is injected only on those browsers and covers
// just the flag codepoints, so the font stack decides per glyph.
polyfillCountryFlagEmojis("Twemoji Country Flags", flagFontUrl);

createRoot(document.querySelector<HTMLDivElement>("#app")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
