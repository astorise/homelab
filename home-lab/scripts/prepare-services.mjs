import { execSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const repoRoot = dirname(dirname(__dirname))

function run(cmd) {
  execSync(cmd, { cwd: repoRoot, stdio: 'inherit' })
}

if (process.platform !== 'win32') {
  console.log('[prepare-services] Non-Windows platform detected, skipping service binary preparation.')
  process.exit(0)
}

const services = ['home-dns', 'home-http', 'home-oidc']
const targetDir = join(repoRoot, 'target', 'release')
const bundleBinDir = join(repoRoot, 'home-lab', 'src-tauri', 'resources', 'bin')

console.log('[prepare-services] Building Windows service binaries...')
for (const svc of services) {
  run(`cargo build -p ${svc} --release`)
}

mkdirSync(bundleBinDir, { recursive: true })
for (const svc of services) {
  const exeName = `${svc}.exe`
  const src = join(targetDir, exeName)
  const dst = join(bundleBinDir, exeName)

  if (!existsSync(src)) {
    throw new Error(`[prepare-services] Missing compiled binary: ${src}`)
  }

  copyFileSync(src, dst)
  const size = statSync(dst).size
  console.log(`[prepare-services] Updated ${dst} (${size} bytes)`)
}
