/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: 'hsl(216 28% 5%)',
        card: 'hsl(216 23% 7%)',
        border: 'hsl(220 13% 14%)',
        muted: 'hsl(216 17% 60%)',
        accent: 'hsl(187 86% 53%)',
      },
      borderRadius: { '2xl': '1rem', xl: '0.75rem' },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
    },
  },
  plugins: [],
}
