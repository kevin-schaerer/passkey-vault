# PassKey Vault

A browser extension for secure passkey (WebAuthn) storage and management. Intercepts WebAuthn API calls to manage passkeys internally without showing the browser's native UI. Supports **Chrome** (Manifest V3) and **Firefox** (Manifest V2).

## Features

- **WebAuthn Interception** - Automatically intercepts passkey creation and authentication
- **Local Storage** - Passkeys stored securely in browser local storage
- **Export/Import** - Full backup with encrypted private keys
- **Cross-Browser** - Works on Chrome and Firefox
- **Brutalist UI** - Clean, high-contrast interface

## Installation

### Install from Chrome Web Store

[Download PassKey Vault](https://chromewebstore.google.com/detail/passkey-vault/lopekoolgoijpmaidblgfgelbkfkgmod)

### Prerequisites

- Node.js 18+
- Chrome 88+ or Firefox 109+

### Build from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/passkey-vault.git
cd passkey-vault

# Install dependencies
npm install

# Build for Chrome
npm run build

# Build for Firefox
npm run build:firefox

# Build for both
npm run build:all
```

### Load in Browser

**Chrome:**

1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `dist/` directory

**Firefox:**

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `dist-firefox/manifest.json`

## Screenshots

![Screenshot 1](https://lh3.googleusercontent.com/dKfp1TeJFxcTcjWDzVWoJNJvl4eDkQS0gM_uOp446x73Ki9EN7HJ9UXkr_1VYr1kMWRdl-2S_Dfv32MygaP-FoMZ5A)

![Screenshot 2](https://lh3.googleusercontent.com/vaVszzxShZYMg9Lv2OTtx6xetvJ4oWnj0fZsLh8XXBbWeV9CDMP6xZlh3EcRtPF31sydsSh5Wx17NrHeQGIFnXNJ9YY)

## Usage

1. Navigate to any site that uses WebAuthn/passkeys
2. When prompted to create a passkey, PassKey Vault will intercept and store it
3. When signing in, PassKey Vault shows a selector if multiple passkeys exist
4. Click the extension icon to view, export, or delete stored passkeys

## Project Structure

```
passkey-vault/
├── src/
│   ├── background/       # Service worker (Chrome) / Background script (Firefox)
│   ├── content/          # Content scripts & WebAuthn injection
│   ├── crypto/           # Encryption utilities
│   ├── ui/               # Popup, import page, in-page UI
│   ├── manifest.json     # Chrome MV3 manifest
│   └── manifest.firefox.json  # Firefox MV2 manifest
├── dist/                 # Chrome build output
├── dist-firefox/         # Firefox build output
├── icon.png              # Extension icon (512x512)
└── build-extension.js    # Build script
```

## Scripts

```bash
npm run build          # Build for Chrome
npm run build:firefox  # Build for Firefox
npm run build:all      # Build for both browsers
npm run zip            # Create Chrome distribution ZIP
npm run zip:firefox    # Create Firefox distribution ZIP
npm run zip:all        # Create both ZIPs
npm run clean          # Remove build directories
npm run typecheck      # Type check without emitting
npm run lint           # Run ESLint
npm run test           # Run tests
```

## How It Works

1. **Content Script** injects a script that overrides `navigator.credentials.create()` and `navigator.credentials.get()`
2. **WebAuthn Interception** captures the credential options and forwards to the background script
3. **Background Script** generates ECDSA P-256 key pairs and creates proper WebAuthn responses
4. **Storage** persists passkeys in browser's local storage
5. **Authentication** signs challenges with stored private keys using proper CBOR/attestation encoding

## Security Notes

- Private keys are stored in browser local storage (not encrypted at rest by default)
- Export files contain private keys - handle with care
- This is a development/research tool - use at your own risk

## Sync & Running Your Own Relay Server

### How Sync Works

The extension syncs passkeys between devices using the [Nostr](https://nostr.com/) WebSocket protocol (NIP-01). All passkey data is **end-to-end encrypted** with a key derived from your recovery phrase before being published to a relay. Only devices that share the same recovery phrase can decrypt the messages.

### ⚠️ Security Considerations for Sync

- **Public relays** (the default) are operated by third parties. While your passkey payload is encrypted, they can see _metadata_: timing, message sizes, relay public keys, and the fact that you are syncing passkeys. Avoid public relays for sensitive deployments.
- The **recovery phrase** is the sole encryption secret — anyone who obtains it can decrypt all synced passkeys. Treat it like a master password.
- Synced passkeys include private keys. Never store the recovery phrase alongside the backup.

### Using Your Own Relay Server

You can point the extension at your own server so that no third-party relay ever sees your encrypted events.

#### 1. Run a Nostr-compatible relay

Any NIP-01 compliant WebSocket relay works. The simplest options:

**Option A — `nostr-rs-relay` (Rust, recommended)**

```bash
# Requires Rust toolchain
cargo install nostr-rs-relay

# Create a minimal config
cat > config.toml <<'EOF'
[database]
data_directory = "/var/lib/nostr-rs-relay"

[network]
address = "0.0.0.0"
port = 8080
EOF

nostr-rs-relay --config config.toml
```

**Option B — `strfry` (C++, high-performance)**

```bash
git clone https://github.com/hoytech/strfry.git
cd strfry
make setup-golpe
make -j4
./strfry relay
```

**Option C — Docker (quickest)**

```bash
docker run -d \
  -p 8080:8080 \
  --name nostr-relay \
  -v nostr-data:/usr/src/app/db \
  scsibug/nostr-rs-relay
```

The relay will be reachable at `ws://localhost:8080` (or `wss://` with TLS termination via nginx/Caddy).

#### 2. (Optional) Add TLS with Nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

#### 3. Configure the extension

When creating or joining a sync chain, enter your relay URL in the **Relay Server URL** field:

```
wss://relay.example.com
```

Leave the field blank to fall back to the default public relays.

The relay URL is stored per sync-chain and displayed in **Sync Settings → Debug → Active Relay(s)**.



MIT
