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
          950: '#050811',
          900: '#0a0f1d',
          850: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
          cyan: '#06b6d4',
          cyanGlow: 'rgba(6, 182, 212, 0.3)',
          emerald: '#10b981',
          emeraldGlow: 'rgba(16, 185, 129, 0.3)',
          crimson: '#ef4444',
          crimsonGlow: 'rgba(239, 68, 68, 0.4)',
          amber: '#f59e0b',
          amberGlow: 'rgba(245, 158, 11, 0.3)',
          purple: '#8b5cf6',
          purpleGlow: 'rgba(139, 92, 246, 0.3)',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      animation: {
        'pulse-danger': 'pulseDanger 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-warning': 'pulseWarning 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'radar-sweep': 'radarSweep 4s linear infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
      },
      keyframes: {
        pulseDanger: {
          '0%, 100%': {
            transform: 'scale(1)',
            boxShadow: '0 0 20px rgba(239, 68, 68, 0.8), 0 0 40px rgba(239, 68, 68, 0.4)',
            borderColor: '#ef4444',
          },
          '50%': {
            transform: 'scale(1.03)',
            boxShadow: '0 0 35px rgba(239, 68, 68, 1), 0 0 60px rgba(239, 68, 68, 0.6)',
            borderColor: '#ff6b6b',
          },
        },
        pulseWarning: {
          '0%, 100%': {
            transform: 'scale(1)',
            boxShadow: '0 0 15px rgba(245, 158, 11, 0.6)',
          },
          '50%': {
            transform: 'scale(1.02)',
            boxShadow: '0 0 25px rgba(245, 158, 11, 0.9)',
          },
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        glowPulse: {
          '0%, 100%': { opacity: '0.6' },
          '50%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
