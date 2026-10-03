#!/usr/bin/env node
'use strict';

// gs-secrets npm shim.
//
// Lazily downloads the platform-specific gs-secrets binary from the GitHub
// release matching this package's version, verifies its SHA-256 checksum,
// caches it, and execs it with the caller's arguments. There is no
// postinstall script, so the package works under --ignore-scripts, pnpm,
// and yarn as well.
//
// Test overrides (all optional):
//   GS_SECRETS_VERSION   version to fetch (default: package.json version)
//   GS_SECRETS_REPO      owner/repo (default: guionardo/gs-secrets)
//   GS_SECRETS_BASE_URL  download base URL (default: https://github.com/<repo>)
//   GS_SECRETS_CACHE_DIR cache directory (default: platform cache dir)

const https = require('https');
const { createHash } = require('crypto');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = process.env.GS_SECRETS_REPO || 'guionardo/gs-secrets';
const VERSION = process.env.GS_SECRETS_VERSION || require('./package.json').version;
const BASE = process.env.GS_SECRETS_BASE_URL || `https://github.com/${REPO}`;
const TAG = `v${VERSION}`;

function die(msg) {
  console.error(`gs-secrets: ${msg}`);
  process.exit(1);
}

function osName() {
  switch (process.platform) {
    case 'darwin':
      return 'darwin';
    case 'linux':
      return 'linux';
    case 'win32':
      return 'windows';
    default:
      die(`unsupported platform: ${process.platform}`);
  }
}

function archName() {
  switch (process.arch) {
    case 'x64':
      return 'amd64';
    case 'arm64':
      return 'arm64';
    default:
      die(`unsupported architecture: ${process.arch}`);
  }
}

function cacheDir() {
  if (process.env.GS_SECRETS_CACHE_DIR) {
    return process.env.GS_SECRETS_CACHE_DIR;
  }
  const base =
    process.platform === 'win32'
      ? process.env.LOCALAPPDATA || os.homedir()
      : path.join(os.homedir(), '.cache');
  return path.join(base, 'gs-secrets', 'bin');
}

function archiveName() {
  const ext = process.platform === 'win32' ? 'zip' : 'tar.gz';
  return `gs-secrets_${VERSION}_${osName()}_${archName()}.${ext}`;
}

function binaryName() {
  return process.platform === 'win32' ? 'gs-secrets.exe' : 'gs-secrets';
}

// get follows up to 5 redirects (GitHub asset URLs redirect to a CDN).
function get(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'gs-secrets-npm' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (url === res.headers.location) {
          return reject(new Error(`redirect loop at ${url}`));
        }
        return resolve(get(res.headers.location));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`GET ${url}: HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
  });
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function expectedChecksum() {
  return get(`${BASE}/releases/download/${TAG}/checksums.txt`).then((body) => {
    const line = body
      .toString('utf8')
      .split('\n')
      .find((l) => l.trim().endsWith(`  ${archiveName()}`) || l.trim().endsWith(` ${archiveName()}`));
    if (!line) {
      die(`checksums.txt has no entry for ${archiveName()}`);
    }
    return line.trim().split(/\s+/)[0];
  });
}

function extract(archive, dest) {
  fs.mkdirSync(dest, { recursive: true });
  if (process.platform === 'win32') {
    const r = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${dest}' -Force`],
      { stdio: 'inherit' }
    );
    if (r.status !== 0) {
      die('failed to extract the archive');
    }
    return;
  }
  const r = spawnSync('tar', ['-xzf', archive, '-C', dest], { stdio: 'inherit' });
  if (r.status !== 0) {
    die('failed to extract the archive');
  }
}

async function main() {
  const bin = path.join(cacheDir(), binaryName());
  if (!fs.existsSync(bin)) {
    const archive = path.join(os.tmpdir(), archiveName());
    console.error(`gs-secrets: downloading ${archiveName()} (${TAG})…`);
    const [data, expected] = await Promise.all([get(`${BASE}/releases/download/${TAG}/${archiveName()}`), expectedChecksum()]);
    const actual = sha256(data);
    if (actual !== expected) {
      die(`checksum mismatch for ${archiveName()}: expected ${expected}, got ${actual}`);
    }
    fs.writeFileSync(archive, data);
    extract(archive, path.dirname(bin));
    fs.unlinkSync(archive);
    if (!fs.existsSync(bin)) {
      die(`binary not found after extraction: ${bin}`);
    }
    try {
      fs.chmodSync(bin, 0o755);
    } catch {
      // Windows has no POSIX modes; ignore.
    }
  }
  const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
  process.exit(r.status === null ? 1 : r.status);
}

main().catch((err) => die(err.message));