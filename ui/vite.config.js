import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Standard Vite + React setup. The app is a static SPA; it talks to AWS
// directly from the browser using temporary credentials from Cognito, so there
// is no backend server to configure here.
export default defineConfig({
  plugins: [react()],
});
