/**
 * PRF (Pseudo-Random Function) Extension Utilities
 *
 * Implements the WebAuthn PRF extension (https://w3c.github.io/webauthn/#prf-extension)
 * which allows passkeys to produce deterministic key material via HMAC-SHA-256.
 *
 * During registration (create):
 *   - clientExtensionResults.prf.enabled = true  (always, since we support PRF)
 *   - clientExtensionResults.prf.results          (only when eval was supplied)
 *
 * During authentication (get):
 *   - clientExtensionResults.prf.results          (when eval was supplied; no enabled field)
 */

export interface PrfValues {
  first?: ArrayBuffer;
  second?: ArrayBuffer;
}

export interface PrfResults {
  results: PrfValues;
}

export interface PrfClientExtensionResult {
  enabled?: boolean;
  results?: {
    first?: string; // base64url-encoded
    second?: string; // base64url-encoded
  };
}

/**
 * Compute a PRF output: HMAC-SHA-256(prfKey, input).
 *
 * Returns a 32-byte ArrayBuffer.
 */
export async function computePrfOutput(
  prfKey: ArrayBuffer,
  input: ArrayBuffer
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw',
    prfKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, input);
}

/**
 * Compute PRF results for both first (and optionally second) eval inputs.
 *
 * Returns null if neither first nor second is provided.
 */
export async function computePrfResults(
  prfKey: ArrayBuffer,
  evalInput: { first?: ArrayBuffer; second?: ArrayBuffer }
): Promise<PrfResults | null> {
  const results: PrfValues = {};
  if (evalInput.first) {
    results.first = await computePrfOutput(prfKey, evalInput.first);
  }
  if (evalInput.second) {
    results.second = await computePrfOutput(prfKey, evalInput.second);
  }
  if (!results.first && !results.second) return null;
  return { results };
}

/**
 * Build the `prf` field for clientExtensionResults.
 *
 * @param prfResults   - Computed PRF results (null if no eval was supplied).
 * @param prfEnabled   - Pass `true` during registration to indicate PRF support.
 *                       Pass `undefined` during authentication (no enabled field).
 * @returns The prf extension result object, or null if there is nothing to include.
 */
export function buildPrfClientExtensionResult(
  prfResults: PrfResults | null,
  prfEnabled?: boolean
): PrfClientExtensionResult | null {
  const prfObj: PrfClientExtensionResult = {};

  if (prfEnabled !== undefined) {
    prfObj.enabled = prfEnabled;
  }

  if (prfResults?.results) {
    const resultMap: { first?: string; second?: string } = {};
    if (prfResults.results.first) {
      resultMap.first = arrayBufferToBase64URL(prfResults.results.first);
    }
    if (prfResults.results.second) {
      resultMap.second = arrayBufferToBase64URL(prfResults.results.second);
    }
    if (resultMap.first || resultMap.second) {
      prfObj.results = resultMap;
    }
  }

  if (Object.keys(prfObj).length === 0) return null;
  return prfObj;
}

/**
 * Encode the PRF extension for inclusion in authenticator data (CBOR format).
 *
 * Produces the CBOR encoding of:
 *   { "prf": { "enabled": true, "results": { "first": <bytes>, "second"?: <bytes> } } }
 *
 * For registration: pass prfEnabled=true (always present when prf extension is requested).
 * For authentication: pass prfEnabled=undefined (only results, no enabled field).
 *
 * Returns null when there is nothing to encode.
 */
export function encodePrfAuthDataExtension(
  prfResults: PrfResults | null,
  prfEnabled?: boolean
): Uint8Array | null {
  if (prfEnabled === undefined && !prfResults?.results) return null;

  const prfEntries: number[] = [];
  let prfEntryCount = 0;

  // Add enabled field (registration only)
  if (prfEnabled !== undefined) {
    prfEntries.push(...encodeTextString('enabled'));
    prfEntries.push(prfEnabled ? 0xf5 : 0xf4); // CBOR true / false
    prfEntryCount++;
  }

  // Add results if present
  if (prfResults?.results) {
    const resultEntries: number[] = [];
    let resultCount = 0;

    if (prfResults.results.first) {
      resultEntries.push(...encodeTextString('first'));
      resultEntries.push(...encodeByteString(new Uint8Array(prfResults.results.first)));
      resultCount++;
    }
    if (prfResults.results.second) {
      resultEntries.push(...encodeTextString('second'));
      resultEntries.push(...encodeByteString(new Uint8Array(prfResults.results.second)));
      resultCount++;
    }

    if (resultCount > 0) {
      prfEntries.push(...encodeTextString('results'));
      prfEntries.push(...encodeMapHeader(resultCount));
      prfEntries.push(...resultEntries);
      prfEntryCount++;
    }
  }

  if (prfEntryCount === 0) return null;

  const prfMap = [...encodeMapHeader(prfEntryCount), ...prfEntries];
  const extensions = [...encodeMapHeader(1), ...encodeTextString('prf'), ...prfMap];
  return new Uint8Array(extensions);
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

function encodeMapHeader(length: number): number[] {
  if (length < 24) return [0xa0 + length];
  if (length < 256) return [0xb8, length];
  return [0xb9, (length >> 8) & 0xff, length & 0xff];
}

function encodeTextString(value: string): number[] {
  const bytes = new TextEncoder().encode(value);
  const header =
    bytes.length < 24
      ? [0x60 + bytes.length]
      : bytes.length < 256
        ? [0x78, bytes.length]
        : [0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff];
  return [...header, ...bytes];
}

function encodeByteString(bytes: Uint8Array): number[] {
  if (bytes.length < 24) return [0x40 + bytes.length, ...bytes];
  if (bytes.length < 256) return [0x58, bytes.length, ...bytes];
  return [0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff, ...bytes];
}

function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] & 0xff);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
