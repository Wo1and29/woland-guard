import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

// index.html and en/index.html set <html lang> statically — each URL is a
// distinct, crawlable language, so it must render deterministically
// regardless of what a previous visit to the *other* URL left in
// localStorage. The URL wins on load; the in-page toggle still overrides it
// for the rest of that session via App.jsx's own localStorage write.
const staticLang = document.documentElement.getAttribute("lang");
if (staticLang === "en" || staticLang === "ru") {
  try {
    localStorage.setItem("wg-lang", staticLang);
  } catch {
    /* private-browsing / storage disabled: App.jsx falls back to "ru" */
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  /*#__PURE__*/ React.createElement(React.StrictMode, null, /*#__PURE__*/ React.createElement(App, null)),
);
