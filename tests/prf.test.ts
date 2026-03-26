import {
  computePrfOutput,
  computePrfResults,
  buildPrfClientExtensionResult,
  encodePrfAuthDataExtension,
  normalizePrfClientExtensionResults,
} from '../src/crypto/prf';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomKey(): ArrayBuffer {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes.buffer;
}

function textBuf(text: string): ArrayBuffer {
  return new TextEncoder().encode(text).buffer;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PRF Extension (src/crypto/prf.ts)', () => {
  describe('computePrfOutput', () => {
    it('produces a 32-byte HMAC-SHA-256 output', async () => {
      const key = randomKey();
      const output = await computePrfOutput(key, textBuf('hello'));
      expect(output.byteLength).toBe(32);
    });

    it('is deterministic for the same key and input', async () => {
      const key = randomKey();
      const a = await computePrfOutput(key, textBuf('same'));
      const b = await computePrfOutput(key, textBuf('same'));
      expect(new Uint8Array(a)).toEqual(new Uint8Array(b));
    });

    it('differs when the input differs', async () => {
      const key = randomKey();
      const a = await computePrfOutput(key, textBuf('input-a'));
      const b = await computePrfOutput(key, textBuf('input-b'));
      expect(new Uint8Array(a)).not.toEqual(new Uint8Array(b));
    });

    it('differs when the key differs', async () => {
      const key1 = randomKey();
      const key2 = randomKey();
      const a = await computePrfOutput(key1, textBuf('same'));
      const b = await computePrfOutput(key2, textBuf('same'));
      expect(new Uint8Array(a)).not.toEqual(new Uint8Array(b));
    });
  });

  describe('computePrfResults', () => {
    it('computes first only', async () => {
      const key = randomKey();
      const res = await computePrfResults(key, { first: textBuf('f') });
      expect(res).not.toBeNull();
      expect(res!.results.first!.byteLength).toBe(32);
      expect(res!.results.second).toBeUndefined();
    });

    it('computes both first and second', async () => {
      const key = randomKey();
      const res = await computePrfResults(key, {
        first: textBuf('f'),
        second: textBuf('s'),
      });
      expect(res).not.toBeNull();
      expect(res!.results.first!.byteLength).toBe(32);
      expect(res!.results.second!.byteLength).toBe(32);
    });

    it('returns null when no inputs are provided', async () => {
      const key = randomKey();
      const res = await computePrfResults(key, {});
      expect(res).toBeNull();
    });

    it('first and second outputs are distinct', async () => {
      const key = randomKey();
      const res = await computePrfResults(key, {
        first: textBuf('first'),
        second: textBuf('second'),
      });
      expect(new Uint8Array(res!.results.first!)).not.toEqual(
        new Uint8Array(res!.results.second!)
      );
    });
  });

  describe('buildPrfClientExtensionResult', () => {
    it('returns enabled:true for registration with prf extension (no eval)', () => {
      const result = buildPrfClientExtensionResult(null, true);
      expect(result).toEqual({ enabled: true });
    });

    it('returns enabled:true + results for registration with eval', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const result = buildPrfClientExtensionResult(prfResults, true);
      expect(result).not.toBeNull();
      expect(result!.enabled).toBe(true);
      expect(typeof result!.results!.first).toBe('string');
    });

    it('returns only results for authentication (no enabled field)', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const result = buildPrfClientExtensionResult(prfResults);
      expect(result).not.toBeNull();
      expect(result!.enabled).toBeUndefined();
      expect(typeof result!.results!.first).toBe('string');
    });

    it('returns null when there is nothing to include', () => {
      expect(buildPrfClientExtensionResult(null)).toBeNull();
    });

    it('encodes result bytes as base64url (no +, /, or = characters)', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const result = buildPrfClientExtensionResult(prfResults, true);
      const b64url = result!.results!.first!;
      expect(b64url).not.toContain('+');
      expect(b64url).not.toContain('/');
      expect(b64url).not.toContain('=');
    });

    it('includes second result when supplied', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, {
        first: textBuf('f'),
        second: textBuf('s'),
      });
      const result = buildPrfClientExtensionResult(prfResults, true);
      expect(result!.results!.second).toBeDefined();
    });
  });

  describe('encodePrfAuthDataExtension', () => {
    it('returns null when nothing to encode', () => {
      expect(encodePrfAuthDataExtension(null)).toBeNull();
    });

    it('encodes enabled:true with no results (registration without eval)', () => {
      const encoded = encodePrfAuthDataExtension(null, true);
      expect(encoded).not.toBeNull();
      // Outer extensions map has exactly 1 entry
      expect(encoded![0]).toBe(0xa1); // CBOR map(1)
    });

    it('encodes results for authentication (no enabled)', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const encoded = encodePrfAuthDataExtension(prfResults);
      expect(encoded).not.toBeNull();
      // Must be larger than the header alone because it contains 32 bytes of HMAC output
      expect(encoded!.length).toBeGreaterThan(32);
    });

    it('encodes both enabled and results for registration with eval', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const withResults = encodePrfAuthDataExtension(prfResults, true);
      const enabledOnly = encodePrfAuthDataExtension(null, true);
      expect(withResults).not.toBeNull();
      expect(withResults!.length).toBeGreaterThan(enabledOnly!.length);
    });

    it('CBOR outer map always starts with map(1) header', () => {
      const encoded1 = encodePrfAuthDataExtension(null, true);
      expect(encoded1![0]).toBe(0xa1);
    });

    it('encodes enabled:false correctly', () => {
      const encoded = encodePrfAuthDataExtension(null, false);
      expect(encoded).not.toBeNull();
      // The byte 0xf4 is CBOR false; it must appear somewhere in the payload
      expect(Array.from(encoded!)).toContain(0xf4);
      expect(Array.from(encoded!)).not.toContain(0xf5); // true must NOT be present
    });

    it('encodes second result when both inputs are supplied', async () => {
      const key = randomKey();
      const prfResultsBoth = await computePrfResults(key, {
        first: textBuf('f'),
        second: textBuf('s'),
      });
      const prfResultsFirst = await computePrfResults(key, { first: textBuf('f') });
      const encodedBoth = encodePrfAuthDataExtension(prfResultsBoth);
      const encodedFirst = encodePrfAuthDataExtension(prfResultsFirst);
      // Two results → larger payload than one result
      expect(encodedBoth!.length).toBeGreaterThan(encodedFirst!.length);
    });
  });

  // ---------------------------------------------------------------------------
  // normalizePrfClientExtensionResults
  // This function is the inverse of buildPrfClientExtensionResult and is used
  // by the injected page script to convert the background's base64url-encoded
  // output back into ArrayBuffers for WebAuthn callers.
  // ---------------------------------------------------------------------------
  describe('normalizePrfClientExtensionResults', () => {
    it('returns null for null/undefined input', () => {
      expect(normalizePrfClientExtensionResults(null)).toBeNull();
      expect(normalizePrfClientExtensionResults(undefined)).toBeNull();
    });

    it('returns null for an empty object', () => {
      expect(normalizePrfClientExtensionResults({})).toBeNull();
    });

    it('preserves enabled:true for registration without eval (no results)', () => {
      const normalized = normalizePrfClientExtensionResults({ enabled: true });
      expect(normalized).not.toBeNull();
      expect(normalized!.enabled).toBe(true);
      expect(normalized!.results).toBeUndefined();
    });

    it('preserves enabled:false', () => {
      const normalized = normalizePrfClientExtensionResults({ enabled: false });
      expect(normalized).not.toBeNull();
      expect(normalized!.enabled).toBe(false);
    });

    it('decodes first result as ArrayBuffer (authentication)', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const encoded = buildPrfClientExtensionResult(prfResults);
      expect(encoded).not.toBeNull();

      const normalized = normalizePrfClientExtensionResults(encoded!);
      expect(normalized).not.toBeNull();
      expect(normalized!.enabled).toBeUndefined();
      expect(normalized!.results?.first).toBeInstanceOf(ArrayBuffer);
      expect((normalized!.results?.first as ArrayBuffer).byteLength).toBe(32);
    });

    it('decodes both first and second results as ArrayBuffers', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, {
        first: textBuf('f'),
        second: textBuf('s'),
      });
      const encoded = buildPrfClientExtensionResult(prfResults, true);
      expect(encoded).not.toBeNull();

      const normalized = normalizePrfClientExtensionResults(encoded!);
      expect(normalized).not.toBeNull();
      expect(normalized!.enabled).toBe(true);
      expect(normalized!.results?.first).toBeInstanceOf(ArrayBuffer);
      expect(normalized!.results?.second).toBeInstanceOf(ArrayBuffer);
    });

    it('preserves enabled:true alongside decoded results (registration with eval)', async () => {
      const key = randomKey();
      const prfResults = await computePrfResults(key, { first: textBuf('f') });
      const encoded = buildPrfClientExtensionResult(prfResults, true);
      expect(encoded).not.toBeNull();
      // Verify the encoded form has both fields so normalization has something to preserve.
      expect(encoded!.enabled).toBe(true);
      expect(typeof encoded!.results?.first).toBe('string');

      const normalized = normalizePrfClientExtensionResults(encoded!);
      expect(normalized).not.toBeNull();
      // The enabled flag must survive normalization (this was the bug).
      expect(normalized!.enabled).toBe(true);
      expect(normalized!.results?.first).toBeInstanceOf(ArrayBuffer);
    });

    it('round-trips: normalized first output matches original HMAC output', async () => {
      const key = randomKey();
      const input = textBuf('round-trip');
      const prfResults = await computePrfResults(key, { first: input });
      const encoded = buildPrfClientExtensionResult(prfResults, true);

      const normalized = normalizePrfClientExtensionResults(encoded!);
      expect(new Uint8Array(normalized!.results!.first!)).toEqual(
        new Uint8Array(prfResults!.results.first!)
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Serialization round-trip (simulating the message-chain fix)
  //
  // chrome.runtime.sendMessage uses JSON serialisation, which destroys
  // ArrayBuffer values (turns them into {}).  The fix in webauthn-inject.ts
  // converts every ArrayBuffer/TypedArray inside the extensions object to a
  // base64url string BEFORE posting the message.  The background's
  // normalizePrfInput already handles string inputs via base64URLToArrayBuffer.
  //
  // These tests verify that the round-trip is bit-for-bit lossless and that
  // PRF output is identical whether the eval input arrived as a raw ArrayBuffer
  // or as a base64url string (the serialized form).
  // ---------------------------------------------------------------------------
  describe('ArrayBuffer→base64url→ArrayBuffer round-trip (serialization fix)', () => {
    // These helpers mirror arrayBufferToBase64URL / base64urlToArrayBuffer from
    // webauthn-inject.ts and src/crypto/prf.ts.  They must stay in sync with those
    // implementations; if the production code changes, update these too.
    function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] & 0xff);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    function base64urlToArrayBuffer(b64url: string): ArrayBuffer {
      const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
      return bytes.buffer;
    }

    it('serializing an ArrayBuffer to base64url and back gives identical bytes', () => {
      const original = textBuf('prf-eval-salt-value');
      const serialized = arrayBufferToBase64URL(original);
      const deserialized = base64urlToArrayBuffer(serialized);
      expect(new Uint8Array(deserialized)).toEqual(new Uint8Array(original));
    });

    it('PRF output is identical whether eval input is the raw ArrayBuffer or the deserialized base64url', async () => {
      const prfKey = randomKey();
      const evalInput = textBuf('deterministic-prf-input');

      // Path A: direct ArrayBuffer (original behaviour pre-fix)
      const directResult = await computePrfOutput(prfKey, evalInput);

      // Path B: serialized to base64url then deserialized (post-fix behaviour)
      const serialized = arrayBufferToBase64URL(evalInput);
      const roundTripped = base64urlToArrayBuffer(serialized);
      const roundTrippedResult = await computePrfOutput(prfKey, roundTripped);

      expect(new Uint8Array(directResult)).toEqual(new Uint8Array(roundTrippedResult));
    });

    it('computePrfResults gives the same output via direct ArrayBuffer and via serialized form', async () => {
      const prfKey = randomKey();
      const first = textBuf('filekey-prf-salt');
      const firstSerialized = arrayBufferToBase64URL(first);
      const firstDeserialized = base64urlToArrayBuffer(firstSerialized);

      const directRes = await computePrfResults(prfKey, { first });
      const roundTrippedRes = await computePrfResults(prfKey, { first: firstDeserialized });

      expect(new Uint8Array(directRes!.results.first!)).toEqual(
        new Uint8Array(roundTrippedRes!.results.first!)
      );
    });

    it('crypto.subtle.digest() result (ArrayBuffer) survives the round-trip unchanged', async () => {
      // Simulates the typical filekey.app usage: PRF salt derived from digest
      const saltInput = new TextEncoder().encode('some-site-specific-info');
      const evalInput = await crypto.subtle.digest('SHA-256', saltInput); // returns ArrayBuffer

      const serialized = arrayBufferToBase64URL(evalInput);
      const deserialized = base64urlToArrayBuffer(serialized);

      expect(new Uint8Array(deserialized)).toEqual(new Uint8Array(evalInput));
    });

    it('TypedArray with non-zero byteOffset serializes only the viewed bytes', () => {
      // serializeExtensions must use view.buffer.slice(byteOffset, byteOffset+byteLength)
      // rather than view.buffer, to avoid serializing the entire backing buffer.
      const backing = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
      const view = backing.subarray(2, 6); // bytes [2,3,4,5], byteOffset=2
      expect(view.byteOffset).toBe(2);

      const serialized = arrayBufferToBase64URL(
        view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength)
      );
      const deserialized = base64urlToArrayBuffer(serialized);

      expect(new Uint8Array(deserialized)).toEqual(new Uint8Array([2, 3, 4, 5]));
      expect(deserialized.byteLength).toBe(4); // NOT 8 (the full backing buffer)
    });
  });
});
