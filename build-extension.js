#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const zlib = require('zlib');
const esbuild = require('esbuild');

const args = process.argv.slice(2);
const targetArg = args.find((arg) => arg.startsWith('--target='));
const target = targetArg ? targetArg.split('=')[1] : 'chrome';

const validTargets = ['chrome', 'firefox', 'all'];
if (!validTargets.includes(target)) {
  console.error(`Invalid target: ${target}. Valid targets: ${validTargets.join(', ')}`);
  process.exit(1);
}

const targets = target === 'all' ? ['chrome', 'firefox'] : [target];

/**
 * Get version info from git.
 *
 * If HEAD is tagged with a valid semver (e.g., v1.2.3):
 *   - version: "1.2.3"
 *   - versionName: "1.2.3"
 *
 * If HEAD is not tagged, use git describe format (like Go pseudo-versions):
 *   - versionName: "1.2.3-11-g93f5879" (base tag + commits since + short hash)
 *   - version: "1.2.3.11" (for Chrome manifest compatibility)
 */
function getVersionFromGit() {
  try {
    // Always fetch tags from remote to ensure we have the latest
    try {
      execSync('git fetch --tags 2>/dev/null', { stdio: 'pipe' });
    } catch {
      // Ignore fetch errors (e.g., offline, no remote)
    }
    // First, try to get exact tag on current commit
    try {
      const exactTag = execSync('git describe --tags --exact-match 2>/dev/null', {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      // Remove 'v' prefix if present
      const versionName = exactTag.startsWith('v') ? exactTag.slice(1) : exactTag;

      // Check if it's a valid Chrome version (1-4 dot-separated integers only)
      if (/^\d+(\.\d+){0,3}$/.test(versionName)) {
        return { version: versionName, versionName };
      }
      // Tag exists but isn't valid for Chrome, fall through to describe
    } catch {
      // No exact tag, continue to git describe
    }

    // Use git describe to get base tag + distance + commit
    const describe = execSync('git describe --tags 2>/dev/null', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();

    // Parse: v1.2.3-11-g93f5879 -> { tag: "1.2.3", distance: 11, hash: "93f5879" }
    const match = describe.match(/^v?(\d+\.\d+\.\d+)-(\d+)-g([a-f0-9]+)$/);
    if (match) {
      const [, baseVersion, distance, hash] = match;
      const versionName = `${baseVersion}-${distance}-${hash}`;
      // Chrome version: append distance as 4th component (1.2.3.11)
      const version = `${baseVersion}.${distance}`;
      return { version, versionName };
    }

    // Fallback: tag exists but doesn't match expected format
    const versionName = describe.startsWith('v') ? describe.slice(1) : describe;
    const commitCount = execSync('git rev-list --count HEAD', { encoding: 'utf8' }).trim();
    return { version: `0.0.${commitCount}`, versionName };
  } catch {
    // No tags at all, use commit count and hash
    const shortHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
    const commitCount = execSync('git rev-list --count HEAD', { encoding: 'utf8' }).trim();

    return {
      version: `0.0.${commitCount}`,
      versionName: `0.0.0-${commitCount}-${shortHash}`,
    };
  }
}

async function main() {
  for (const browserTarget of targets) {
    await buildForTarget(browserTarget);
  }
}

async function buildForTarget(browserTarget) {
  const isFirefox = browserTarget === 'firefox';
  const distDir = isFirefox ? 'dist-firefox' : 'dist';

  console.log(`\n🏗️  Building PassKey Vault for ${browserTarget.toUpperCase()}...\n`);

  // Get version from git
  const { version, versionName } = getVersionFromGit();
  console.log(`📌 Version: ${versionName} (manifest: ${version})`);

  console.log(`🧹 Cleaning ${distDir} directory...`);
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  console.log('📦 Bundling with esbuild...');

  const commonOptions = {
    bundle: true,
    minify: false,
    sourcemap: false,
    target: ['chrome88', 'firefox109'],
    format: 'iife',
    platform: 'browser',
  };

  try {
    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/background/background.ts'],
      outfile: `${distDir}/background.js`,
    });
    console.log('  ✅ background.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/content/content.ts'],
      outfile: `${distDir}/content.js`,
    });

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/passkey-ui.ts'],
      outfile: `${distDir}/passkey-ui.js`,
    });

    const passkeyUiJs = fs.readFileSync(`${distDir}/passkey-ui.js`, 'utf8');
    const contentJs = fs.readFileSync(`${distDir}/content.js`, 'utf8');
    fs.writeFileSync(`${distDir}/content.js`, passkeyUiJs + '\n' + contentJs);
    fs.unlinkSync(`${distDir}/passkey-ui.js`);
    console.log('  ✅ content.js (bundled with passkey-ui)');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/content/webauthn-inject.ts'],
      outfile: `${distDir}/webauthn-inject.js`,
    });
    console.log('  ✅ webauthn-inject.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/popup.ts'],
      outfile: `${distDir}/popup.js`,
    });
    console.log('  ✅ popup.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/import.ts'],
      outfile: `${distDir}/import.js`,
    });
    console.log('  ✅ import.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/emergency-ui.ts'],
      outfile: `${distDir}/emergency-ui.js`,
    });
    console.log('  ✅ emergency-ui.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/sync-setup.ts'],
      outfile: `${distDir}/sync-setup.js`,
    });
    console.log('  ✅ sync-setup.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/sync-settings.ts'],
      outfile: `${distDir}/sync-settings.js`,
    });
    console.log('  ✅ sync-settings.js');
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    process.exit(1);
  }

  console.log('📋 Processing manifest...');
  const manifestFile = isFirefox ? 'src/manifest.firefox.json' : 'src/manifest.json';
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));

  // Set version from git
  manifest.version = version;
  // version_name is Chrome-only; Firefox MV2 doesn't support it and logs a warning
  if (!isFirefox) {
    manifest.version_name = versionName;
  }

  if (isFirefox) {
    manifest.background.scripts = ['background.js'];
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources = ['webauthn-inject.js'];
  } else {
    manifest.background.service_worker = 'background.js';
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources[0].resources = ['webauthn-inject.js'];
  }

  fs.writeFileSync(`${distDir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log('  ✅ manifest.json');

  const iconsDir = path.join(distDir, 'icons');
  fs.mkdirSync(iconsDir, { recursive: true });

  console.log('🎨 Processing icons...');

  const iconSizes = [16, 48, 128];

  // Prefer icon.svg → icon.png → generated fallback (in that order)
  const sourceSvg = 'icon.svg';
  const sourcePng = 'icon.png';

  let iconsGenerated = false;

  // Try rsvg-convert (librsvg) for SVG → PNG
  if (!iconsGenerated && fs.existsSync(sourceSvg)) {
    try {
      for (const size of iconSizes) {
        const outputPath = path.join(iconsDir, `icon${size}.png`);
        execSync(`rsvg-convert -w ${size} -h ${size} "${sourceSvg}" -o "${outputPath}"`, {
          stdio: 'pipe',
        });
      }
      console.log('  ✅ Rendered icons from icon.svg (rsvg-convert)');
      iconsGenerated = true;
    } catch {
      // rsvg-convert not available, try next tool
    }
  }

  // Try Inkscape for SVG → PNG
  if (!iconsGenerated && fs.existsSync(sourceSvg)) {
    try {
      for (const size of iconSizes) {
        const outputPath = path.join(iconsDir, `icon${size}.png`);
        execSync(
          `inkscape --export-type=png --export-width=${size} --export-height=${size} --export-filename="${outputPath}" "${sourceSvg}"`,
          { stdio: 'pipe' }
        );
      }
      console.log('  ✅ Rendered icons from icon.svg (inkscape)');
      iconsGenerated = true;
    } catch {
      // Inkscape not available, try next tool
    }
  }

  // Try ImageMagick for PNG → PNG (resize)
  if (!iconsGenerated && fs.existsSync(sourcePng)) {
    try {
      for (const size of iconSizes) {
        const outputPath = path.join(iconsDir, `icon${size}.png`);
        execSync(`convert "${sourcePng}" -resize ${size}x${size} "${outputPath}"`, {
          stdio: 'pipe',
        });
      }
      console.log('  ✅ Resized icons from icon.png (ImageMagick)');
      iconsGenerated = true;
    } catch {
      // ImageMagick not available, fall through to generated icons
    }
  }

  if (!iconsGenerated) {
    console.warn('  ⚠️  No image conversion tool found, generating built-in icons');
    generatePlaceholderIcons(iconsDir, iconSizes);
  }

  function generatePlaceholderIcons(dir, sizes) {
    for (const size of sizes) {
      const png = createIconPNG(size);
      fs.writeFileSync(path.join(dir, `icon${size}.png`), png);
    }
    console.log('  ✅ Generated built-in PassKey Vault icons');
  }

  /**
   * Renders the PassKey Vault icon (dark navy background, blue shield, gold key)
   * as a valid RGBA PNG without any external dependencies.
   */
  function createIconPNG(size) {
    const S = size;

    // ── colour palette ──────────────────────────────────────────────────
    const BG      = [15,  21,  53,  255]; // #0f1535 dark navy
    const SHIELD  = [58,  120, 220, 255]; // #3a78dc vivid blue
    const SHIELD2 = [30,  80,  175, 255]; // #1e50af deeper blue (gradient bottom)
    const KEY     = [255, 210, 0,   255]; // #ffd200 gold
    const KEY2    = [220, 170, 0,   255]; // #d8aa00 darker gold (gradient bottom)
    const TRANSP  = [0,   0,   0,   0  ];

    function clamp(v) { return v < 0 ? 0 : v > 1 ? 1 : v; }
    function smooth(a, b, x) {
      // EPSILON prevents division by zero when a === b
      const EPSILON = 1e-9;
      const t = clamp((x - a) / (b - a + EPSILON));
      return t * t * (3 - 2 * t);
    }
    function lerp(a, b, t) { return a + (b - a) * t; }

    // px[y][x] = [R, G, B, A]
    const px = Array.from({ length: S }, () =>
      Array.from({ length: S }, () => [...TRANSP])
    );

    // 1) Rounded-square background ─────────────────────────────────────
    const CR  = S * 0.22;  // corner radius
    const CX  = S / 2, CY = S / 2;
    for (let y = 0; y < S; y++) {
      for (let x = 0; x < S; x++) {
        const dx = Math.max(Math.abs(x + 0.5 - CX) - (S / 2 - CR), 0);
        const dy = Math.max(Math.abs(y + 0.5 - CY) - (S / 2 - CR), 0);
        const d  = Math.sqrt(dx * dx + dy * dy);
        const a  = smooth(CR + 0.7, CR - 0.3, d);
        if (a > 0) px[y][x] = [BG[0], BG[1], BG[2], Math.round(255 * a)];
      }
    }

    // 2) Shield (heater shield) ─────────────────────────────────────────
    const SL = S * 0.12, SR = S * 0.88;
    const ST = S * 0.09, SB = S * 0.93;
    const SW = (SR - SL) / 2;
    const SM = (SL + SR) / 2;

    function shieldAlpha(x, y) {
      const nx = (x + 0.5 - SM) / SW;
      const ny = (y + 0.5 - ST) / (SB - ST);
      if (ny < 0) return 0;
      const maxNx = ny <= 0.68
        ? (ny < 0.14 ? 1 - 0.06 * (1 - ny / 0.14) ** 2 : 1)
        : 1 - (ny - 0.68) / 0.32;
      return smooth(maxNx + 0.012, maxNx - 0.012, Math.abs(nx));
    }

    for (let y = 0; y < S; y++) {
      for (let x = 0; x < S; x++) {
        if (px[y][x][3] === 0) continue;
        const a = shieldAlpha(x, y);
        if (a > 0) {
          const gy = clamp((y + 0.5 - ST) / (SB - ST));
          const sc = [
            Math.round(lerp(SHIELD[0], SHIELD2[0], gy * 0.35)),
            Math.round(lerp(SHIELD[1], SHIELD2[1], gy * 0.35)),
            Math.round(lerp(SHIELD[2], SHIELD2[2], gy * 0.35)),
          ];
          const bgA = px[y][x][3];
          px[y][x] = [
            Math.round(lerp(px[y][x][0], sc[0], a)),
            Math.round(lerp(px[y][x][1], sc[1], a)),
            Math.round(lerp(px[y][x][2], sc[2], a)),
            bgA,
          ];
        }
      }
    }

    // 3) Key symbol ─────────────────────────────────────────────────────
    const KCX  = SM;
    const KCY  = ST + (SB - ST) * 0.47;
    const KOR  = SW * 0.30;
    const KIR  = SW * 0.14;
    const BLY  = KCY;
    const BLX0 = KCX + KOR * 0.7;
    const BLX1 = SM + SW * 0.70;
    const BLH  = SW * 0.12;
    const TW   = SW * 0.10;
    const TH   = SW * 0.19;
    const T1X  = BLX0 + (BLX1 - BLX0) * 0.28;
    const T2X  = BLX0 + (BLX1 - BLX0) * 0.57;
    // Feather radius for antialiasing edges: at least 0.5px, scales with icon size
    const MIN_FEATHER_RADIUS = 0.5;
    const FEATHER_SCALE_FACTOR = 0.005;
    const F = Math.max(MIN_FEATHER_RADIUS, S * FEATHER_SCALE_FACTOR);

    for (let y = 0; y < S; y++) {
      for (let x = 0; x < S; x++) {
        if (px[y][x][3] === 0) continue;
        const xc = x + 0.5, yc = y + 0.5;
        const dist = Math.sqrt((xc - KCX) ** 2 + (yc - KCY) ** 2);

        // key bow (annular ring)
        const rm  = (KOR + KIR) / 2;
        const rw  = (KOR - KIR) / 2;
        const aRing = smooth(rw + F, rw - F, Math.abs(dist - rm));

        // horizontal blade
        const aBlade =
          smooth(BLX0 - F, BLX0 + F, xc) *
          smooth(BLX1 + F, BLX1 - F, xc) *
          smooth(BLH + F, BLH - F, Math.abs(yc - BLY));

        // teeth (downward notches)
        let aTeeth = 0;
        for (const tx of [T1X, T2X]) {
          const ix = smooth(tx - F, tx + F, xc) * smooth(tx + TW + F, tx + TW - F, xc);
          const iy = smooth(BLY - F, BLY + F, yc) * smooth(BLY + TH + F, BLY + TH - F, yc);
          aTeeth = Math.max(aTeeth, ix * iy);
        }

        const aKey = Math.max(aRing, aBlade, aTeeth);
        if (aKey > 0) {
          const ky = clamp((yc - ST) / (SB - ST));
          const kc = [
            Math.round(lerp(KEY[0], KEY2[0], ky * 0.25)),
            Math.round(lerp(KEY[1], KEY2[1], ky * 0.25)),
            Math.round(lerp(KEY[2], KEY2[2], ky * 0.25)),
          ];
          px[y][x] = [
            Math.round(lerp(px[y][x][0], kc[0], aKey)),
            Math.round(lerp(px[y][x][1], kc[1], aKey)),
            Math.round(lerp(px[y][x][2], kc[2], aKey)),
            px[y][x][3],
          ];
        }
      }
    }

    // ── Encode as PNG (RGBA, 8-bit) ────────────────────────────────────
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

    const ihdr = Buffer.alloc(25);
    ihdr.writeUInt32BE(13, 0);
    ihdr.write('IHDR', 4);
    ihdr.writeUInt32BE(S, 8);
    ihdr.writeUInt32BE(S, 12);
    ihdr.writeUInt8(8, 16);   // bit depth
    ihdr.writeUInt8(6, 17);   // colour type: RGBA
    ihdr.writeUInt8(0, 18); ihdr.writeUInt8(0, 19); ihdr.writeUInt8(0, 20);
    ihdr.writeUInt32BE(zlib.crc32(ihdr.subarray(4, 21)), 21);

    const rawData = Buffer.alloc(S * (1 + S * 4));
    for (let y = 0; y < S; y++) {
      rawData[y * (1 + S * 4)] = 0; // filter: None
      for (let x = 0; x < S; x++) {
        const off = y * (1 + S * 4) + 1 + x * 4;
        rawData[off]     = px[y][x][0];
        rawData[off + 1] = px[y][x][1];
        rawData[off + 2] = px[y][x][2];
        rawData[off + 3] = px[y][x][3];
      }
    }

    const compressed = zlib.deflateSync(rawData);
    const idat = Buffer.alloc(compressed.length + 12);
    idat.writeUInt32BE(compressed.length, 0);
    idat.write('IDAT', 4);
    compressed.copy(idat, 8);
    idat.writeUInt32BE(
      zlib.crc32(Buffer.concat([Buffer.from('IDAT'), compressed])),
      compressed.length + 8
    );

    const iend = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);

    return Buffer.concat([signature, ihdr, idat, iend]);
  }

  console.log('📄 Copying static assets...');

  if (fs.existsSync('src/ui/emergency.html')) {
    fs.copyFileSync('src/ui/emergency.html', `${distDir}/emergency.html`);
    console.log('  ✅ emergency.html');
  }

  if (fs.existsSync('src/ui/popup.html')) {
    fs.copyFileSync('src/ui/popup.html', `${distDir}/popup.html`);
    console.log('  ✅ popup.html');
  }

  if (fs.existsSync('src/ui/popup.css')) {
    fs.copyFileSync('src/ui/popup.css', `${distDir}/popup.css`);
    console.log('  ✅ popup.css');
  }

  if (fs.existsSync('src/ui/import.html')) {
    fs.copyFileSync('src/ui/import.html', `${distDir}/import.html`);
    console.log('  ✅ import.html');
  }

  if (fs.existsSync('src/ui/sync-setup.html')) {
    fs.copyFileSync('src/ui/sync-setup.html', `${distDir}/sync-setup.html`);
    console.log('  ✅ sync-setup.html');
  }

  if (fs.existsSync('src/ui/sync-settings.html')) {
    fs.copyFileSync('src/ui/sync-settings.html', `${distDir}/sync-settings.html`);
    console.log('  ✅ sync-settings.html');
  }

  let totalSize = 0;
  const files = fs
    .readdirSync(distDir)
    .filter((f) => !fs.statSync(path.join(distDir, f)).isDirectory());
  for (const file of files) {
    totalSize += fs.statSync(path.join(distDir, file)).size;
  }
  fs.readdirSync(iconsDir).forEach((file) => {
    totalSize += fs.statSync(path.join(iconsDir, file)).size;
  });

  console.log(`\n🎉 ${browserTarget.toUpperCase()} Build Complete!`);
  console.log(`📦 Extension: ${manifest.name} v${versionName}`);
  console.log(`📁 Output: ${distDir}/`);
  console.log(`💾 Total size: ${(totalSize / 1024).toFixed(1)}KB`);

  if (isFirefox) {
    console.log(`
🦊 Ready to install in Firefox!

Installation (Temporary):
1. Open about:debugging#/runtime/this-firefox
2. Click "Load Temporary Add-on..."
3. Select the manifest.json file in the "${distDir}" directory
`);
  } else {
    console.log(`
🚀 Ready to install in Chrome!

Installation:
1. Open chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the "${distDir}" directory
`);
  }
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
