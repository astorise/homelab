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

const services = ['home-dns', 'home-http', 'home-s3', 'home-oidc']
const targetDir = join(repoRoot, 'target', 'release')
const bundleBinDir = join(repoRoot, 'home-lab', 'src-tauri', 'resources', 'bin')

mkdirSync(bundleBinDir, { recursive: true })

// If all service binaries are already present in resources/bin (e.g. downloaded
// from CI artifacts), skip the cargo build to avoid rebuilding in CI.
const allPrebuilt = [...services, 'home-lab-cert'].every(
  svc => existsSync(join(bundleBinDir, `${svc}.exe`))
)

if (allPrebuilt) {
  console.log('[prepare-services] All binaries already present in resources/bin, skipping cargo build.')
} else {
  console.log('[prepare-services] Building Windows service binaries...')
  for (const svc of services) {
    run(`cargo build -p ${svc} --release`)
  }
  run('cargo build --manifest-path home-lab/src-tauri/Cargo.toml --bin home-lab-cert --release')

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

  {
    const exeName = 'home-lab-cert.exe'
    const src = join(targetDir, exeName)
    const dst = join(bundleBinDir, exeName)
    if (!existsSync(src)) {
      throw new Error(`[prepare-services] Missing compiled binary: ${src}`)
    }
    copyFileSync(src, dst)
    const size = statSync(dst).size
    console.log(`[prepare-services] Updated ${dst} (${size} bytes)`)
  }
}
