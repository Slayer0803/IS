/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070b14',
          900: '#0c1222',
          850: '#111a33',
          800: '#162344',
          700: '#233870',
          500: '#3b82f6',
          400: '#60a5fa',
        }
      }
    },
  },
  plugins: [],
}

