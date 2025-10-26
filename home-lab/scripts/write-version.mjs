import { execSync } from 'node:child_process'
import { writeFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const repoRoot = dirname(dirname(__dirname))

function sh(cmd) {
  try { return execSync(cmd, { cwd: repoRoot, stdio: ['ignore','pipe','ignore'] }).toString().trim() } catch { return '' }
}

const pkg = JSON.parse(execSync('node -p "JSON.stringify(require(\'./home-lab/package.json\'))"', { cwd: repoRoot }).toString())
const version = pkg.version || '0.0.0'
const sha = sh('git rev-parse --short HEAD') || process.env.GITHUB_SHA?.slice(0,7) || 'unknown'
const tag = sh('git describe --tags --always') || sha
const run = process.env.GITHUB_RUN_NUMBER || ''
const when = new Date().toISOString()

const content = `app=home-lab\nversion=${version}\ntag=${tag}\nsha=${sha}\nrun=${run}\nbuilt=${when}\n`
const outDir = join(repoRoot, 'home-lab', 'src-tauri', 'resources')
mkdirSync(outDir, { recursive: true })
writeFileSync(join(outDir, 'version.txt'), content)
console.log('[write-version] Wrote version.txt with:', { version, tag, sha, run, when })

