/**
 * Secure Storage Module for PassKey Vault
 * Provides encrypted storage for sensitive data like seed hashes and passkeys
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';

const ENCRYPTION_CONFIG = {
  algorithm: 'AES-256-GCM',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits for GCM
  saltLength: 32, // 256 bits
  iterations: 100000,
} as const;

const STORAGE_KEYS = {
  MASTER_KEY_CHECK: 'passext_master_key_check',
  ENCRYPTED_SYNC_CONFIG: 'passext_encrypted_sync_config',
  ENCRYPTED_PASSKEYS: 'passext_encrypted_passkeys',
  ENCRYPTION_SALT: 'passext_encryption_salt',
  PIN_ENCRYPTED_KEY: 'passext_pin_encrypted_key',
  PIN_SALT: 'passext_pin_salt',
} as const;

// Key used in chrome.storage.session to persist the encryption key across
// service-worker suspensions within a single browser session.
const SESSION_STORAGE_KEY = 'passext_session_key';

// Value encrypted and stored to verify the master password is correct.
const MASTER_KEY_CHECK_VALUE = 'passkey-vault-check';

export interface SecureStorageConfig {
  seedHash: string;
  chainId: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
  // Random salt used for PBKDF2 key derivation in sync (null if not yet set)
  syncSalt: string | null;
}

export interface EncryptedData {
  data: string; // Base64 encrypted data
  iv: string; // Base64 IV
  salt: string; // Base64 salt
  version: string;
}

/**
 * Derives an encryption key from a master password using the WebCrypto API.
 * Using crypto.subtle.deriveBits instead of the @noble/hashes synchronous
 * pbkdf2 avoids blocking the event loop for several seconds (100,000 iterations
 * on a background thread), which in Firefox MV2 caused the message-response
 * port to become invalid before sendResponse could be called.
 */
async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: ENCRYPTION_CONFIG.iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    ENCRYPTION_CONFIG.keyLength * 8
  );
  return new Uint8Array(bits);
}

/**
 * Encrypts data with a derived key
 */
function encryptData(data: string, key: Uint8Array): EncryptedData {
  const iv = randomBytes(ENCRYPTION_CONFIG.ivLength);
  const cipher = gcm(key, iv);
  const encrypted = cipher.encrypt(new TextEncoder().encode(data));

  return {
    data: uint8ArrayToBase64(encrypted),
    iv: uint8ArrayToBase64(iv),
    salt: '', // Salt is stored separately at the account level
    version: '2.0',
  };
}

/**
 * Decrypts data with a derived key
 */
function decryptData(encryptedData: EncryptedData, key: Uint8Array): string {
  const iv = base64ToUint8Array(encryptedData.iv);
  const encrypted = base64ToUint8Array(encryptedData.data);

  const cipher = gcm(key, iv);
  const decrypted = cipher.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}

/**
 * Reliable wrapper around chrome.storage.local.get using the callback-based
 * API. In Firefox MV2 non-persistent background pages the Promise-based
 * variant can resolve with `undefined` instead of the expected result object.
 * The callback form works correctly in both Chrome and Firefox.
 */
function storageGet(key: string | string[]): Promise<Record<string, any>> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(key, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(result ?? {});
      }
    });
  });
}

function storageSet(data: Record<string, any>): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(data, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

function storageRemove(keys: string | string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.remove(keys, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

/**
 * chrome.storage.session helpers – available in Chrome MV3 only.
 * In Firefox (or any environment where session storage is absent) these
 * functions are no-ops so that the rest of the code can call them safely.
 */
function sessionStorageGet(key: string): Promise<Record<string, any>> {
  if (!chrome.storage?.session) {
    return Promise.resolve({});
  }
  return new Promise((resolve, reject) => {
    chrome.storage.session.get(key, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(result ?? {});
      }
    });
  });
}

function sessionStorageSet(data: Record<string, any>): Promise<void> {
  if (!chrome.storage?.session) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    chrome.storage.session.set(data, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

function sessionStorageRemove(key: string): void {
  if (!chrome.storage?.session) {
    return;
  }
  chrome.storage.session.remove(key, () => {
    if (chrome.runtime.lastError) {
      console.warn('SecureStorage: failed to remove session key:', chrome.runtime.lastError.message);
    }
  });
}

function uint8ArrayToBase64(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Securely wipes a Uint8Array from memory
 */
function secureWipe(arr: Uint8Array): void {
  crypto.getRandomValues(arr);
  arr.fill(0);
}

/**
 * SecureStorage class for managing encrypted sensitive data
 */
export class SecureStorage {
  private encryptionKey: Uint8Array | null = null;
  private salt: Uint8Array | null = null;
  private isUnlocked = false;
  private _restoringFromSession = false;

  /**
   * Initialize secure storage with a master password
   * This must be called before any other operations
   */
  async initialize(masterPassword: string): Promise<boolean> {
    try {
      // Load or create salt
      const saltResult = await storageGet(STORAGE_KEYS.ENCRYPTION_SALT);
      if (saltResult[STORAGE_KEYS.ENCRYPTION_SALT]) {
        this.salt = base64ToUint8Array(saltResult[STORAGE_KEYS.ENCRYPTION_SALT]);
      } else {
        // First time setup - generate new salt
        this.salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
        await storageSet({
          [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(this.salt),
        });
      }

      // Derive encryption key
      this.encryptionKey = await deriveKeyFromPassword(masterPassword, this.salt);

      // Verify password is correct (if we have existing data)
      const checkResult = await storageGet(STORAGE_KEYS.MASTER_KEY_CHECK);
      if (checkResult[STORAGE_KEYS.MASTER_KEY_CHECK]) {
        try {
          const decrypted = decryptData(
            checkResult[STORAGE_KEYS.MASTER_KEY_CHECK],
            this.encryptionKey
          );
          if (decrypted !== MASTER_KEY_CHECK_VALUE) {
            this.lock();
            return false;
          }
        } catch {
          this.lock();
          return false;
        }
      } else {
        // First time - store check value
        const checkData = encryptData(MASTER_KEY_CHECK_VALUE, this.encryptionKey);
        await storageSet({
          [STORAGE_KEYS.MASTER_KEY_CHECK]: checkData,
        });
      }

      this.isUnlocked = true;
      await sessionStorageSet({ [SESSION_STORAGE_KEY]: uint8ArrayToBase64(this.encryptionKey!) });
      return true;
    } catch (error) {
      console.error('SecureStorage initialization failed:', error);
      this.lock();
      return false;
    }
  }

  /**
   * Check if secure storage is unlocked
   */
  isStorageUnlocked(): boolean {
    return this.isUnlocked && this.encryptionKey !== null;
  }

  /**
   * Check if a master password has been set up
   */
  async isSetup(): Promise<boolean> {
    const result = await storageGet(STORAGE_KEYS.MASTER_KEY_CHECK);
    return !!result[STORAGE_KEYS.MASTER_KEY_CHECK];
  }

  /**
   * Lock the secure storage, wiping encryption key from memory
   */
  lock(): void {
    if (this.encryptionKey) {
      secureWipe(this.encryptionKey);
      this.encryptionKey = null;
    }
    this.isUnlocked = false;
    // Clear the session key so the vault cannot be automatically restored
    // after a manual lock (fire-and-forget; failure is non-critical).
    sessionStorageRemove(SESSION_STORAGE_KEY);
  }

  /**
   * Set auto-lock timeout in milliseconds (no-op – kept for API compatibility)
   */
  setAutoLockTimeout(_ms: number): void {
    // Auto-lock is disabled; vault only locks manually or on browser/session close
  }

  /**
   * Attempt to restore the encryption key from chrome.storage.session.
   * This handles the case where the Chrome MV3 service worker was suspended
   * and the in-memory key was wiped, but the browser session is still active.
   * Returns true if the key was successfully restored (or was already loaded).
   */
  async tryRestoreFromSession(): Promise<boolean> {
    if (this.isUnlocked && this.encryptionKey !== null) {
      return true; // Already unlocked
    }
    if (this._restoringFromSession) {
      // Another concurrent call is already restoring; wait briefly and recheck.
      await new Promise((resolve) => setTimeout(resolve, 50));
      return this.isUnlocked && this.encryptionKey !== null;
    }
    this._restoringFromSession = true;
    try {
      const result = await sessionStorageGet(SESSION_STORAGE_KEY);
      const keyB64 = result[SESSION_STORAGE_KEY];
      if (!keyB64) {
        return false;
      }

      const key = base64ToUint8Array(keyB64);

      // Verify the restored key is still valid against the stored check value
      const checkResult = await storageGet(STORAGE_KEYS.MASTER_KEY_CHECK);
      if (!checkResult[STORAGE_KEYS.MASTER_KEY_CHECK]) {
        secureWipe(key);
        return false;
      }

      try {
        const decrypted = decryptData(checkResult[STORAGE_KEYS.MASTER_KEY_CHECK], key);
        if (decrypted !== MASTER_KEY_CHECK_VALUE) {
          secureWipe(key);
          sessionStorageRemove(SESSION_STORAGE_KEY);
          return false;
        }
      } catch {
        secureWipe(key);
        sessionStorageRemove(SESSION_STORAGE_KEY);
        return false;
      }

      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = key;
      this.isUnlocked = true;
      return true;
    } catch (error) {
      console.error('SecureStorage: failed to restore from session:', error);
      return false;
    } finally {
      this._restoringFromSession = false;
    }
  }

  /**
   * Store sync configuration securely
   */
  async storeSyncConfig(config: SecureStorageConfig): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(config), this.encryptionKey!);
    await storageSet({
      [STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG]: encrypted,
    });
  }

  /**
   * Retrieve sync configuration
   */
  async getSyncConfig(): Promise<SecureStorageConfig | null> {
    this.ensureUnlocked();

    const result = await storageGet(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
    if (!result[STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG]) {
      return null;
    }

    try {
      const decrypted = decryptData(
        result[STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG],
        this.encryptionKey!
      );
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to decrypt sync config:', error);
      return null;
    }
  }

  /**
   * Delete sync configuration
   */
  async deleteSyncConfig(): Promise<void> {
    await storageRemove(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
  }

  /**
   * Store passkeys securely
   */
  async storePasskeys(passkeys: any[]): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(passkeys), this.encryptionKey!);
    await storageSet({
      [STORAGE_KEYS.ENCRYPTED_PASSKEYS]: encrypted,
    });
  }

  /**
   * Retrieve passkeys
   */
  async getPasskeys(): Promise<any[]> {
    this.ensureUnlocked();

    const result = await storageGet(STORAGE_KEYS.ENCRYPTED_PASSKEYS);
    if (!result[STORAGE_KEYS.ENCRYPTED_PASSKEYS]) {
      return [];
    }

    try {
      const decrypted = decryptData(result[STORAGE_KEYS.ENCRYPTED_PASSKEYS], this.encryptionKey!);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to decrypt passkeys:', error);
      return [];
    }
  }

  /**
   * Add or update a single passkey
   */
  async upsertPasskey(passkey: any): Promise<void> {
    const passkeys = await this.getPasskeys();
    const index = passkeys.findIndex((p) => p.id === passkey.id);

    if (index >= 0) {
      passkeys[index] = passkey;
    } else {
      passkeys.push(passkey);
    }

    await this.storePasskeys(passkeys);
  }

  /**
   * Delete a passkey by ID
   */
  async deletePasskey(passkeyId: string): Promise<boolean> {
    const passkeys = await this.getPasskeys();
    const filtered = passkeys.filter((p) => p.id !== passkeyId && p.credentialId !== passkeyId);

    if (filtered.length < passkeys.length) {
      await this.storePasskeys(filtered);
      return true;
    }
    return false;
  }

  /**
   * Get passkeys for a specific relying party
   */
  async getPasskeysForRp(rpId: string): Promise<any[]> {
    const passkeys = await this.getPasskeys();
    return passkeys.filter((p) => p.rpId === rpId);
  }

  /**
   * Change the master password
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    // Verify current password
    if (!this.isUnlocked) {
      const verified = await this.initialize(currentPassword);
      if (!verified) {
        return false;
      }
    }

    try {
      // Get all existing data
      const syncConfig = await this.getSyncConfig();
      const passkeys = await this.getPasskeys();

      // Generate new salt
      const newSalt = randomBytes(ENCRYPTION_CONFIG.saltLength);
      const newKey = await deriveKeyFromPassword(newPassword, newSalt);

      // Re-encrypt everything with new key
      await storageSet({
        [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(newSalt),
      });

      // Update internal state
      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = newKey;
      this.salt = newSalt;

      // Store new check value
      const checkData = encryptData(MASTER_KEY_CHECK_VALUE, this.encryptionKey);
      await storageSet({
        [STORAGE_KEYS.MASTER_KEY_CHECK]: checkData,
      });

      // Re-encrypt and store data
      if (syncConfig) {
        await this.storeSyncConfig(syncConfig);
      }
      if (passkeys.length > 0) {
        await this.storePasskeys(passkeys);
      }

      // Update the session key to reflect the new encryption key
      await sessionStorageSet({ [SESSION_STORAGE_KEY]: uint8ArrayToBase64(this.encryptionKey!) });

      return true;
    } catch (error) {
      console.error('Failed to change master password:', error);
      return false;
    }
  }

  /**
   * Check if a PIN has been configured
   */
  async hasPin(): Promise<boolean> {
    const result = await storageGet(STORAGE_KEYS.PIN_ENCRYPTED_KEY);
    return !!result[STORAGE_KEYS.PIN_ENCRYPTED_KEY];
  }

  /**
   * Set a PIN. The vault must already be unlocked.
   * Encrypts the current master key under the PIN so it can be used to unlock later.
   */
  async setPin(pin: string): Promise<void> {
    this.ensureUnlocked();

    const pinSalt = randomBytes(ENCRYPTION_CONFIG.saltLength);
    const pinKey = await deriveKeyFromPassword(pin, pinSalt);
    const encryptedKey = encryptData(uint8ArrayToBase64(this.encryptionKey!), pinKey);
    secureWipe(pinKey);

    await storageSet({
      [STORAGE_KEYS.PIN_SALT]: uint8ArrayToBase64(pinSalt),
      [STORAGE_KEYS.PIN_ENCRYPTED_KEY]: encryptedKey,
    });
  }

  /**
   * Clear the PIN (vault must be unlocked)
   */
  async clearPin(): Promise<void> {
    this.ensureUnlocked();
    await storageRemove([STORAGE_KEYS.PIN_ENCRYPTED_KEY, STORAGE_KEYS.PIN_SALT]);
  }

  /**
   * Unlock the vault using a PIN.
   * Returns true if successful.
   */
  async unlockWithPin(pin: string): Promise<boolean> {
    try {
      const [pinKeyResult, encResult] = await Promise.all([
        storageGet(STORAGE_KEYS.PIN_SALT),
        storageGet(STORAGE_KEYS.PIN_ENCRYPTED_KEY),
      ]);

      const pinSaltB64 = pinKeyResult[STORAGE_KEYS.PIN_SALT];
      const pinEncData = encResult[STORAGE_KEYS.PIN_ENCRYPTED_KEY];
      if (!pinSaltB64 || !pinEncData) {
        return false; // No PIN configured
      }

      const pinSalt = base64ToUint8Array(pinSaltB64);
      const pinKey = await deriveKeyFromPassword(pin, pinSalt);

      let masterKeyB64: string;
      try {
        masterKeyB64 = decryptData(pinEncData, pinKey);
      } catch {
        secureWipe(pinKey);
        return false; // Wrong PIN
      }
      secureWipe(pinKey);

      const masterKey = base64ToUint8Array(masterKeyB64);

      // Verify the master key is correct
      const checkResult = await storageGet(STORAGE_KEYS.MASTER_KEY_CHECK);
      if (checkResult[STORAGE_KEYS.MASTER_KEY_CHECK]) {
        try {
          const decrypted = decryptData(checkResult[STORAGE_KEYS.MASTER_KEY_CHECK], masterKey);
          if (decrypted !== MASTER_KEY_CHECK_VALUE) {
            secureWipe(masterKey);
            return false;
          }
        } catch {
          secureWipe(masterKey);
          return false;
        }
      }

      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = masterKey;
      this.isUnlocked = true;
      await sessionStorageSet({ [SESSION_STORAGE_KEY]: uint8ArrayToBase64(this.encryptionKey!) });
      return true;
    } catch (error) {
      console.error('SecureStorage PIN unlock failed:', error);
      this.lock();
      return false;
    }
  }

  /**
   * Wipe all secure data (emergency reset)
   */
  async emergencyWipe(): Promise<void> {
    this.lock();
    await storageRemove([
      STORAGE_KEYS.MASTER_KEY_CHECK,
      STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
      STORAGE_KEYS.ENCRYPTED_PASSKEYS,
      STORAGE_KEYS.ENCRYPTION_SALT,
      STORAGE_KEYS.PIN_ENCRYPTED_KEY,
      STORAGE_KEYS.PIN_SALT,
    ]);
  }

  /**
   * Ensure storage is unlocked before operations
   */
  private ensureUnlocked(): void {
    if (!this.isUnlocked || !this.encryptionKey) {
      throw new Error('Secure storage is locked. Please unlock with master password.');
    }
  }

  /**
   * Generate a random salt for sync PBKDF2 operations
   */
  generateSyncSalt(): string {
    const salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
    return uint8ArrayToBase64(salt);
  }
}

// Export singleton instance
export const secureStorage = new SecureStorage();
