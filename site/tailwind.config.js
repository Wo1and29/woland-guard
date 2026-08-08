/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./en/index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        body: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      colors: {
        signal: "#7fc2e0",
        critical: "#e2695a",
        warning: "#dba55a",
        info: "#93aec2",
      },
      borderRadius: { DEFAULT: "9999px" },
    },
  },
  plugins: [],
};
