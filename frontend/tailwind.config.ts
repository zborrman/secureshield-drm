import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          bg: "#0F172A",      // Глубокий фон (Slate 900)
          surface: "#1E293B", // Карточки и инпуты (Slate 800)
          primary: "#3B82F6", // Основной синий (Blue 500)
          accent: "#06B6D4",  // Защищенные элементы (Cyan 500)
          success: "#22C55E", // Статусы успеха
          error: "#EF4444",   // Ошибки и выход
        },
        text: {
          main: "#F8FAFC",    // Основной светлый текст
          muted: "#94A3B8",   // Вторичный текст
        }
      },
      backgroundImage: {
        'secure-gradient': 'radial-gradient(circle at top left, #1E293B, #0F172A)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
};

export default config;
