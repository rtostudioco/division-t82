// DIVISION T82 · db push sin npm en la máquina destino.
// Uso: node tools\db-push.js "C:\ProgramData\VULNCHECK-T82"
// Ejecuta `prisma db push` con la CLI empaquetada en tools/prisma-cli (idempotente).
'use strict'
const { execFileSync } = require('child_process')
const path = require('path')
const os = require('os')

const dataDir = process.argv[2]
  || path.join(process.env.ProgramData || path.join(os.homedir(), 'AppData', 'Local'), 'VULNCHECK-T82')

const root = path.resolve(__dirname, '..') // raíz del payload
process.env.DATABASE_URL = 'file:' + dataDir.replace(/\\/g, '/') + '/vulncheck.db'

const prismaCli = path.join(root, 'tools', 'prisma-cli', 'node_modules', 'prisma', 'build', 'index.js')
if (!require('fs').existsSync(prismaCli)) {
  console.error('[T82] Falta tools/prisma-cli — reinstala con el instalador completo.')
  process.exit(1)
}

try {
  execFileSync(process.execPath, [prismaCli, 'db', 'push', '--skip-generate'], {
    cwd: root, // prisma/schema.prisma se descubre desde aquí
    env: process.env,
    stdio: 'inherit',
  })
} catch (err) {
  console.error('[T82] prisma db push falló:', err.message)
  process.exit(1)
}
