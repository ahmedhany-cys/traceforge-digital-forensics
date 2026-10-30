/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "Liberation Mono", "monospace"],
      },
      colors: {
        ink: {
          950: "#070a10",
          900: "#0b1019",
          850: "#0f1520",
          800: "#131b28",
          700: "#1b2535",
          600: "#263246",
          500: "#3a475d",
          400: "#5b6b84",
          300: "#8a98ae",
          200: "#b9c3d3",
          100: "#dfe5ee",
        },
        accent: { 400: "#3fd0c9", 500: "#1fb5ae", 600: "#14928c" },
      },
      boxShadow: { panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)" },
    },
  },
  plugins: [],
};
