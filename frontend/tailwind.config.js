/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0e14',
          panel: '#0f1621',
          border: '#1c2733',
          accent: '#00f5d4',
          accent2: '#7c3aed',
          danger: '#ff3860',
          warning: '#ffb020',
          success: '#22c55e',
          muted: '#64748b',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        glow: '0 0 20px rgba(0, 245, 212, 0.25)',
      },
    },
  },
  plugins: [],
}
