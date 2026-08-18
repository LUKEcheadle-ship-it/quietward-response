import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#070b14",
        panel: "#0e1626",
        line: "#22304a",
        cyan: "#62d5ef"
      },
      boxShadow: {
        glow: "0 0 40px rgba(72, 187, 220, 0.08)"
      }
    }
  },
  plugins: []
};

export default config;
