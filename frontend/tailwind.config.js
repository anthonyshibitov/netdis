/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors : {
        'ndblue': '#5b92e5',
        'ndgrey': '#2a2b2a',
        'ccc': '#ccc',
      }
    }
  },
  plugins: [],
}
