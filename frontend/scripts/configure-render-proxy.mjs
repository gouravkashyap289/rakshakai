import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const input = process.argv[2];
let backend;
try {
  backend = new URL(input);
} catch {
  console.error('Usage: npm run configure:backend -- https://your-backend.onrender.com');
  process.exit(1);
}

if (backend.protocol !== 'https:' || backend.username || backend.password || backend.pathname !== '/' || backend.search || backend.hash) {
  console.error('Provide only the HTTPS backend origin, with no path, query, or credentials.');
  process.exit(1);
}

const config = {
  $schema: 'https://openapi.vercel.sh/vercel.json',
  framework: 'vite',
  buildCommand: 'npm run build',
  outputDirectory: 'dist',
  rewrites: [{ source: '/api/:path*', destination: `${backend.origin}/api/:path*` }],
};

writeFileSync(fileURLToPath(new URL('../vercel.json', import.meta.url)), `${JSON.stringify(config, null, 2)}\n`);
console.log(`Vercel /api requests now proxy to ${backend.origin}`);
