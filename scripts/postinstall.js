const fs = require('fs');
const path = require('path');

// Create placeholder icon files if they don't exist
const iconsPath = path.join(__dirname, '..', 'src', 'icons');
const iconSizes = [16, 48, 128];

if (!fs.existsSync(iconsPath)) {
  fs.mkdirSync(iconsPath, { recursive: true });
}

// PassKey Vault icon SVG: dark navy background, blue shield, gold key
const createIconSvg = (size) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="${size}" height="${size}">
  <rect width="512" height="512" rx="112" ry="112" fill="#0f1535"/>
  <path d="M62,46 H450 Q462,46 462,58 V358 Q462,382 440,402 L272,470 Q256,478 240,470 L72,402 Q50,382 50,358 V58 Q50,46 62,46 Z" fill="#3a78dc"/>
  <circle cx="210" cy="232" r="68" fill="#ffd200"/>
  <circle cx="210" cy="232" r="33" fill="#3a78dc"/>
  <rect x="258" y="201" width="196" height="62" rx="8" fill="#ffd200"/>
  <rect x="318" y="263" width="46" height="52" rx="6" fill="#ffd200"/>
  <rect x="394" y="263" width="46" height="52" rx="6" fill="#ffd200"/>
</svg>`;
};

iconSizes.forEach(size => {
  const iconPath = path.join(iconsPath, `icon${size}.png`);
  if (!fs.existsSync(iconPath)) {
    // Create an SVG placeholder (build script will convert to PNG)
    const svgPath = iconPath.replace('.png', '.svg');
    fs.writeFileSync(svgPath, createIconSvg(size));
    console.log(`Created SVG placeholder for icon${size}.png`);
  }
});

console.log('Post-install setup completed');
