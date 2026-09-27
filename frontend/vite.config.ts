import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({plugins:[react(),tailwindcss()],server:{port:5173,strictPort:true,proxy:{'/api':process.env.RAKSHAK_BACKEND_URL||'http://127.0.0.1:8002'}},preview:{port:5173,strictPort:true,proxy:{'/api':process.env.RAKSHAK_BACKEND_URL||'http://127.0.0.1:8002'}},build:{chunkSizeWarningLimit:1500}});
