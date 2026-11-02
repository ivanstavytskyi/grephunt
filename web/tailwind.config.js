/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Geist Variable", "Geist", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["Geist Mono Variable", "Geist Mono", "ui-monospace", "monospace"],
      },
      colors: {
        ink: {
          bg: "#0c0f14",
          panel: "#131820",
          raised: "#1b212b",
          line: "#2a3240",
          text: "#e8edf5",
          muted: "#8b98ab",
        },
        signal: "#d6f25c",
      },
    },
  },
  plugins: [],
};
