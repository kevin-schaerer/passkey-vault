import {
  computePrfOutput,
  computePrfResults,
  buildPrfClientExtensionResult,
  encodePrfAuthDataExtension,
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
});
