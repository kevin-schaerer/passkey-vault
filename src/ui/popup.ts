/**
 * Popup UI for PassKey Vault
 *
 * Displays and manages stored passkeys with full export/import support.
 * All passkey data is read/written via the background service worker using
 * the secure encrypted storage (AES-256-GCM, master password required).
 */

(function () {
  'use strict';

  const EXPORT_VERSION = '1.0';

  // DOM elements
  let loadingEl: HTMLElement;
  let emptyStateEl: HTMLElement;
  let passkeyListEl: HTMLElement;
  let passkeyCountEl: HTMLElement;
  let refreshBtn: HTMLButtonElement;
  let exportFullBtn: HTMLButtonElement;
  let importBtn: HTMLButtonElement;
  let clearBtn: HTMLButtonElement;
  let syncSettingsBtn: HTMLButtonElement;
  let lockBtn: HTMLButtonElement;
  let settingsBtn: HTMLButtonElement;
  let confirmModal: HTMLElement;
  let searchInput: HTMLInputElement;
  let searchClearBtn: HTMLButtonElement;
  let debugLoggingToggle: HTMLInputElement;
  let setupPanelEl: HTMLElement;
  let unlockPanelEl: HTMLElement;
  let settingsModal: HTMLElement;

  // Tracks whether vault is currently unlocked (used to show/hide Lock button)
  let vaultUnlocked = false;

  let allPasskeys: any[] = [];

  // Initialize popup when DOM is loaded
  document.addEventListener('DOMContentLoaded', () => {
    initializeElements();
    createConfirmModal();
    loadDebugLoggingState();
    loadPasskeys();
    setupEventListeners();
  });

  function initializeElements(): void {
    loadingEl = document.getElementById('loading') as HTMLElement;
    emptyStateEl = document.getElementById('empty-state') as HTMLElement;
    passkeyListEl = document.getElementById('passkey-list') as HTMLElement;
    passkeyCountEl = document.getElementById('passkey-count') as HTMLElement;
    refreshBtn = document.getElementById('refresh-btn') as HTMLButtonElement;
    exportFullBtn = document.getElementById('export-full-btn') as HTMLButtonElement;
    importBtn = document.getElementById('import-btn') as HTMLButtonElement;
    clearBtn = document.getElementById('clear-btn') as HTMLButtonElement;
    syncSettingsBtn = document.getElementById('sync-settings-btn') as HTMLButtonElement;
    lockBtn = document.getElementById('lock-btn') as HTMLButtonElement;
    settingsBtn = document.getElementById('settings-btn') as HTMLButtonElement;
    searchInput = document.getElementById('search-input') as HTMLInputElement;
    searchClearBtn = document.getElementById('search-clear') as HTMLButtonElement;
    debugLoggingToggle = document.getElementById('debug-logging-toggle') as HTMLInputElement;
    setupPanelEl = document.getElementById('setup-panel') as HTMLElement;
    unlockPanelEl = document.getElementById('unlock-panel') as HTMLElement;
    settingsModal = document.getElementById('settings-modal') as HTMLElement;
  }

  // ─── Master password panels ──────────────────────────────────────────────

  function showSetupPanel(): void {
    loadingEl.style.display = 'none';
    emptyStateEl.style.display = 'none';
    passkeyListEl.style.display = 'none';
    unlockPanelEl.style.display = 'none';
    setupPanelEl.style.display = 'flex';
    passkeyCountEl.textContent = '';
    setLockButtonVisible(false);
  }

  function showUnlockPanel(): void {
    loadingEl.style.display = 'none';
    emptyStateEl.style.display = 'none';
    passkeyListEl.style.display = 'none';
    setupPanelEl.style.display = 'none';
    unlockPanelEl.style.display = 'flex';
    passkeyCountEl.textContent = '';
    setLockButtonVisible(false);
    // Check if PIN is available and pre-select that tab if so
    chrome.runtime.sendMessage({ type: 'HAS_PIN' }).then((resp) => {
      if (resp?.hasPin) {
        activateUnlockTab('pin');
      }
    }).catch(() => {/* ignore */});
  }

  function setLockButtonVisible(visible: boolean): void {
    vaultUnlocked = visible;
    if (lockBtn) {
      lockBtn.style.display = visible ? '' : 'none';
    }
  }

  function hideSecurityPanels(): void {
    setupPanelEl.style.display = 'none';
    unlockPanelEl.style.display = 'none';
  }

  function setupSecurityPanelListeners(): void {
    // Setup panel
    const setupForm = document.getElementById('setup-form') as HTMLFormElement;
    if (setupForm) {
      setupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPw = (document.getElementById('setup-password') as HTMLInputElement).value;
        const confirmPw = (document.getElementById('setup-password-confirm') as HTMLInputElement).value;
        const errEl = document.getElementById('setup-error') as HTMLElement;

        if (newPw.length < 8) {
          errEl.textContent = 'Password must be at least 8 characters.';
          return;
        }
        if (newPw !== confirmPw) {
          errEl.textContent = 'Passwords do not match.';
          return;
        }
        errEl.textContent = '';

        const submitBtn = setupForm.querySelector('button[type="submit"]') as HTMLButtonElement;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Setting up…';

        try {
          const response = await chrome.runtime.sendMessage({
            type: 'SETUP_MASTER_PASSWORD',
            payload: { password: newPw },
          });
          if (response?.success) {
            showNotification('Master password set up successfully!');
            hideSecurityPanels();
            loadPasskeys();
          } else {
            errEl.textContent = response?.error || 'Setup failed. Please try again.';
          }
        } catch (err) {
          errEl.textContent = 'Communication error. Please try again.';
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Set Up Vault';
        }
      });
    }

    // Unlock panel – tab switching
    const tabPassword = document.getElementById('unlock-tab-password') as HTMLButtonElement;
    const tabPin = document.getElementById('unlock-tab-pin') as HTMLButtonElement;
    if (tabPassword && tabPin) {
      tabPassword.addEventListener('click', () => activateUnlockTab('password'));
      tabPin.addEventListener('click', () => activateUnlockTab('pin'));
    }

    // Unlock panel – form submission
    const unlockForm = document.getElementById('unlock-form') as HTMLFormElement;
    if (unlockForm) {
      unlockForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const errEl = document.getElementById('unlock-error') as HTMLElement;
        errEl.textContent = '';

        const submitBtn = unlockForm.querySelector('button[type="submit"]') as HTMLButtonElement;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Unlocking…';

        const isPinMode = tabPin?.classList.contains('active');

        try {
          let response: any;
          if (isPinMode) {
            const pin = (document.getElementById('unlock-pin') as HTMLInputElement).value;
            response = await chrome.runtime.sendMessage({
              type: 'UNLOCK_WITH_PIN',
              payload: { pin },
            });
          } else {
            const pw = (document.getElementById('unlock-password') as HTMLInputElement).value;
            response = await chrome.runtime.sendMessage({
              type: 'UNLOCK_SECURE_STORAGE',
              payload: { password: pw },
            });
          }
          if (response?.success) {
            hideSecurityPanels();
            loadPasskeys();
          } else {
            errEl.textContent =
              response?.error || (isPinMode ? 'Incorrect PIN.' : 'Incorrect password. Please try again.');
          }
        } catch (err) {
          errEl.textContent = 'Communication error. Please try again.';
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Unlock';
        }
      });
    }
  }

  function activateUnlockTab(tab: 'password' | 'pin'): void {
    const tabPassword = document.getElementById('unlock-tab-password') as HTMLButtonElement;
    const tabPin = document.getElementById('unlock-tab-pin') as HTMLButtonElement;
    const passwordGroup = document.getElementById('unlock-password-group') as HTMLElement;
    const pinGroup = document.getElementById('unlock-pin-group') as HTMLElement;

    if (tab === 'pin') {
      tabPin?.classList.add('active');
      tabPassword?.classList.remove('active');
      pinGroup.style.display = '';
      passwordGroup.style.display = 'none';
    } else {
      tabPassword?.classList.add('active');
      tabPin?.classList.remove('active');
      passwordGroup.style.display = '';
      pinGroup.style.display = 'none';
    }
    const errEl = document.getElementById('unlock-error') as HTMLElement;
    if (errEl) errEl.textContent = '';
  }

  // ─── Settings modal ──────────────────────────────────────────────────────

  function openSettingsModal(): void {
    settingsModal.style.display = 'flex';
    // Reset forms
    (document.getElementById('change-password-form') as HTMLFormElement)?.reset();
    (document.getElementById('set-pin-form') as HTMLFormElement)?.reset();
    const cpErr = document.getElementById('change-password-error') as HTMLElement;
    if (cpErr) cpErr.textContent = '';
    const spErr = document.getElementById('set-pin-error') as HTMLElement;
    if (spErr) spErr.textContent = '';

    // Load PIN status
    chrome.runtime.sendMessage({ type: 'HAS_PIN' }).then((resp) => {
      const pinStatusText = document.getElementById('pin-status-text') as HTMLElement;
      const clearPinBtn = document.getElementById('clear-pin-btn') as HTMLButtonElement;
      if (resp?.success) {
        pinStatusText.textContent = resp.hasPin ? 'A PIN is currently set.' : 'No PIN configured.';
        clearPinBtn.style.display = resp.hasPin ? '' : 'none';
      }
    }).catch(() => {/* ignore */});
  }

  function closeSettingsModal(): void {
    settingsModal.style.display = 'none';
  }

  function setupSettingsModalListeners(): void {
    const closeBtn = document.getElementById('settings-close-btn') as HTMLButtonElement;
    if (closeBtn) {
      closeBtn.addEventListener('click', closeSettingsModal);
    }

    settingsModal.addEventListener('click', (e) => {
      if (e.target === settingsModal) closeSettingsModal();
    });

    // Change password form
    const changePasswordForm = document.getElementById('change-password-form') as HTMLFormElement;
    if (changePasswordForm) {
      changePasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const currentPw = (document.getElementById('current-password') as HTMLInputElement).value;
        const newPw = (document.getElementById('new-password') as HTMLInputElement).value;
        const confirmPw = (document.getElementById('new-password-confirm') as HTMLInputElement).value;
        const errEl = document.getElementById('change-password-error') as HTMLElement;

        if (newPw.length < 8) {
          errEl.textContent = 'New password must be at least 8 characters.';
          return;
        }
        if (newPw !== confirmPw) {
          errEl.textContent = 'New passwords do not match.';
          return;
        }
        errEl.textContent = '';

        const submitBtn = changePasswordForm.querySelector('button[type="submit"]') as HTMLButtonElement;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Changing…';

        try {
          const response = await chrome.runtime.sendMessage({
            type: 'CHANGE_MASTER_PASSWORD',
            payload: { currentPassword: currentPw, newPassword: newPw },
          });
          if (response?.success) {
            showNotification('Master password changed successfully!');
            changePasswordForm.reset();
            closeSettingsModal();
          } else {
            errEl.textContent = response?.error || 'Failed to change password.';
          }
        } catch (err) {
          errEl.textContent = 'Communication error. Please try again.';
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Change Password';
        }
      });
    }

    // Set PIN form
    const setPinForm = document.getElementById('set-pin-form') as HTMLFormElement;
    if (setPinForm) {
      setPinForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPin = (document.getElementById('new-pin') as HTMLInputElement).value;
        const confirmPin = (document.getElementById('new-pin-confirm') as HTMLInputElement).value;
        const errEl = document.getElementById('set-pin-error') as HTMLElement;

        if (!/^\d{4,8}$/.test(newPin)) {
          errEl.textContent = 'PIN must be 4–8 digits.';
          return;
        }
        if (newPin !== confirmPin) {
          errEl.textContent = 'PINs do not match.';
          return;
        }
        errEl.textContent = '';

        const submitBtn = setPinForm.querySelector('button[type="submit"]') as HTMLButtonElement;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Setting…';

        try {
          const response = await chrome.runtime.sendMessage({
            type: 'SET_PIN',
            payload: { pin: newPin },
          });
          if (response?.success) {
            showNotification('PIN set successfully!');
            setPinForm.reset();
            const pinStatusText = document.getElementById('pin-status-text') as HTMLElement;
            if (pinStatusText) pinStatusText.textContent = 'A PIN is currently set.';
            const clearPinBtn = document.getElementById('clear-pin-btn') as HTMLButtonElement;
            if (clearPinBtn) clearPinBtn.style.display = '';
          } else {
            errEl.textContent = response?.error || 'Failed to set PIN.';
          }
        } catch (err) {
          errEl.textContent = 'Communication error. Please try again.';
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Set PIN';
        }
      });
    }

    // Clear PIN button
    const clearPinBtn = document.getElementById('clear-pin-btn') as HTMLButtonElement;
    if (clearPinBtn) {
      clearPinBtn.addEventListener('click', async () => {
        const errEl = document.getElementById('set-pin-error') as HTMLElement;
        clearPinBtn.disabled = true;
        try {
          const response = await chrome.runtime.sendMessage({ type: 'CLEAR_PIN' });
          if (response?.success) {
            showNotification('PIN removed.');
            const pinStatusText = document.getElementById('pin-status-text') as HTMLElement;
            if (pinStatusText) pinStatusText.textContent = 'No PIN configured.';
            clearPinBtn.style.display = 'none';
            (document.getElementById('set-pin-form') as HTMLFormElement)?.reset();
          } else {
            if (errEl) errEl.textContent = response?.error || 'Failed to clear PIN.';
          }
        } catch (err) {
          if (errEl) errEl.textContent = 'Communication error. Please try again.';
        } finally {
          clearPinBtn.disabled = false;
        }
      });
    }
  }

  // ─── Confirm modal ───────────────────────────────────────────────────────

  function createConfirmModal(): void {
    confirmModal = document.createElement('div');
    confirmModal.id = 'confirm-modal';
    confirmModal.className = 'modal-overlay';
    confirmModal.innerHTML = `
      <div class="modal-content">
        <div class="modal-icon">⚠️</div>
        <h3 class="modal-title"></h3>
        <p class="modal-message"></p>
        <div class="modal-actions">
          <button class="btn btn-secondary modal-cancel">Cancel</button>
          <button class="btn btn-danger modal-confirm">Confirm</button>
        </div>
      </div>
    `;
    confirmModal.style.display = 'none';
    document.body.appendChild(confirmModal);

    confirmModal.addEventListener('click', (e) => {
      if (e.target === confirmModal) {
        hideConfirmModal();
      }
    });
  }

  function showConfirmModal(
    title: string,
    message: string,
    confirmText: string = 'Confirm',
    isDanger: boolean = true
  ): Promise<boolean> {
    return new Promise((resolve) => {
      const titleEl = confirmModal.querySelector('.modal-title') as HTMLElement;
      const messageEl = confirmModal.querySelector('.modal-message') as HTMLElement;
      const confirmBtn = confirmModal.querySelector('.modal-confirm') as HTMLButtonElement;
      const cancelBtn = confirmModal.querySelector('.modal-cancel') as HTMLButtonElement;

      titleEl.textContent = title;
      messageEl.textContent = message;
      confirmBtn.textContent = confirmText;
      confirmBtn.className = isDanger
        ? 'btn btn-danger modal-confirm'
        : 'btn btn-primary modal-confirm';

      confirmModal.style.display = 'flex';

      const cleanup = () => {
        confirmBtn.removeEventListener('click', onConfirm);
        cancelBtn.removeEventListener('click', onCancel);
        hideConfirmModal();
      };

      const onConfirm = () => { cleanup(); resolve(true); };
      const onCancel = () => { cleanup(); resolve(false); };

      confirmBtn.addEventListener('click', onConfirm);
      cancelBtn.addEventListener('click', onCancel);
    });
  }

  function hideConfirmModal(): void {
    confirmModal.style.display = 'none';
  }

  // ─── Event listeners ─────────────────────────────────────────────────────

  function setupEventListeners(): void {
    refreshBtn.addEventListener('click', loadPasskeys);
    exportFullBtn.addEventListener('click', exportPasskeysFull);
    importBtn.addEventListener('click', openImportPage);
    clearBtn.addEventListener('click', clearAllPasskeys);

    if (lockBtn) {
      lockBtn.addEventListener('click', lockVault);
    }
    if (settingsBtn) {
      settingsBtn.addEventListener('click', openSettingsModal);
    }

    const syncSettingsBtnEl = document.getElementById('sync-settings-btn') as HTMLButtonElement;
    if (syncSettingsBtnEl) {
      syncSettingsBtnEl.addEventListener('click', openSyncSettings);
    }

    searchInput.addEventListener('input', handleSearch);
    searchClearBtn.addEventListener('click', clearSearch);

    const importEmptyBtn = document.getElementById('import-btn-empty');
    if (importEmptyBtn) {
      importEmptyBtn.addEventListener('click', openImportPage);
    }

    debugLoggingToggle.addEventListener('change', handleDebugLoggingToggle);

    setupSecurityPanelListeners();
    setupSettingsModalListeners();
  }

  async function lockVault(): Promise<void> {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'LOCK_SECURE_STORAGE' });
      if (response?.success) {
        setLockButtonVisible(false);
        showUnlockPanel();
      } else {
        showNotification(response?.error || 'Failed to lock vault', 'error');
      }
    } catch (error) {
      console.error('Failed to lock vault:', error);
      showNotification('Failed to lock vault', 'error');
    }
  }

  async function loadDebugLoggingState(): Promise<void> {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_DEBUG_LOGGING' });
      if (response.success) {
        debugLoggingToggle.checked = response.enabled;
      }
    } catch (error) {
      console.error('Failed to load debug logging state:', error);
    }
  }

  async function handleDebugLoggingToggle(): Promise<void> {
    const enabled = debugLoggingToggle.checked;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'SET_DEBUG_LOGGING',
        payload: { enabled },
      });
      if (response.success) {
        showNotification(`Debug logging ${enabled ? 'enabled' : 'disabled'}`);
      } else {
        showNotification('Failed to toggle debug logging', 'error');
        debugLoggingToggle.checked = !enabled;
      }
    } catch (error) {
      console.error('Failed to toggle debug logging:', error);
      showNotification('Failed to toggle debug logging', 'error');
      debugLoggingToggle.checked = !enabled;
    }
  }

  function openSyncSettings(): void {
    chrome.tabs.create({ url: chrome.runtime.getURL('sync-settings.html') });
  }

  // ─── Search ──────────────────────────────────────────────────────────────

  function handleSearch(): void {
    const query = searchInput.value.trim().toLowerCase();
    searchClearBtn.style.display = query ? 'block' : 'none';

    if (!query) {
      renderPasskeys(allPasskeys);
      return;
    }

    const filtered = filterAndSortPasskeys(allPasskeys, query);
    if (filtered.length === 0) {
      showNoResults(query);
    } else {
      renderPasskeys(filtered);
    }
  }

  function clearSearch(): void {
    searchInput.value = '';
    searchClearBtn.style.display = 'none';
    renderPasskeys(allPasskeys);
    searchInput.focus();
  }

  function filterAndSortPasskeys(passkeys: any[], query: string): any[] {
    const hasAtSymbol = query.includes('@');

    const scored = passkeys
      .map((passkey) => {
        const domain = (passkey.rpId || '').toLowerCase();
        const username = (passkey.user?.name || '').toLowerCase();
        const domainMatch = domain.includes(query);
        const usernameMatch = username.includes(query);

        if (!domainMatch && !usernameMatch) return null;

        let score = 0;
        if (hasAtSymbol) {
          if (usernameMatch) score += username.startsWith(query) ? 100 : 50;
          if (domainMatch) score += domain.startsWith(query) ? 40 : 20;
        } else {
          if (domainMatch) score += domain.startsWith(query) ? 100 : 50;
          if (usernameMatch) score += username.startsWith(query) ? 40 : 20;
        }

        return { passkey, score };
      })
      .filter((item): item is { passkey: any; score: number } => item !== null);

    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return (b.passkey.createdAt || 0) - (a.passkey.createdAt || 0);
    });

    return scored.map((item) => item.passkey);
  }

  function showNoResults(query: string): void {
    passkeyListEl.innerHTML = `
      <div class="no-results">
        <div class="no-results-icon">🔍</div>
        <p>No passkeys found for "${popupEscapeHtml(query)}"</p>
      </div>
    `;
    passkeyListEl.style.display = 'flex';
  }

  function openImportPage(): void {
    chrome.tabs.create({ url: chrome.runtime.getURL('import.html') });
  }

  // ─── Passkey loading ─────────────────────────────────────────────────────

  /**
   * Directly checks chrome.storage.local (no background message) to determine
   * whether the master password has ever been set up.  Used as a fallback when
   * the background returns undefined (Firefox MV2 non-persistent event-page
   * timing issue: the background process may be mid-start when the first popup
   * message arrives, causing sendResponse to be lost and sendMessage to resolve
   * with undefined instead of the expected response object).
   */
  function checkNeedsSetup(): Promise<boolean> {
    return new Promise((resolve) => {
      chrome.storage.local.get('passext_master_key_check', (result) => {
        resolve(!result?.passext_master_key_check);
      });
    });
  }

  async function loadPasskeys(): Promise<void> {
    try {
      loadingEl.style.display = 'flex';
      emptyStateEl.style.display = 'none';
      passkeyListEl.style.display = 'none';
      hideSecurityPanels();

      searchInput.value = '';
      searchClearBtn.style.display = 'none';

      const response = await chrome.runtime.sendMessage({ type: 'LIST_PASSKEYS', payload: {} });

      loadingEl.style.display = 'none';

      if (!response) {
        // Firefox MV2: the background event page may not have sent a response
        // (race between page wake-up and sendResponse).  Read storage directly
        // to determine whether setup is required or the vault is just locked.
        const needsSetup = await checkNeedsSetup();
        if (needsSetup) {
          showSetupPanel();
        } else {
          showUnlockPanel();
        }
        return;
      }

      if (response.requiresSetup) {
        showSetupPanel();
        return;
      }

      if (response.requiresUnlock) {
        showUnlockPanel();
        return;
      }

      if (!response.success) {
        throw new Error(response.error || 'Failed to load passkeys');
      }

      setLockButtonVisible(true);

      const passkeys: any[] = response.passkeys || [];
      allPasskeys = passkeys;

      passkeyCountEl.textContent = `${passkeys.length} passkey${passkeys.length !== 1 ? 's' : ''}`;

      if (passkeys.length === 0) {
        emptyStateEl.style.display = 'block';
      } else {
        renderPasskeys(passkeys);
      }
    } catch (error) {
      console.error('Error loading passkeys:', error);
      // Restore loadingEl visibility before replacing its content so the error
      // is actually visible (if the error is thrown after loadingEl was already
      // hidden, the catch block would silently show nothing — blank window).
      loadingEl.style.display = 'flex';
      loadingEl.innerHTML = `
        <div class="error-state">
          <div class="error-icon">⚠️</div>
          <p>Failed to load passkeys</p>
          <button onclick="location.reload()" class="btn btn-secondary">Retry</button>
        </div>
      `;
    }
  }

  // ─── Rendering ───────────────────────────────────────────────────────────

  function renderPasskeys(passkeys: any[]): void {
    passkeyListEl.innerHTML = '';

    const sortedPasskeys = [...passkeys].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    sortedPasskeys.forEach((passkey) => {
      const item = createPasskeyItem(passkey);
      passkeyListEl.appendChild(item);
    });

    passkeyListEl.style.display = 'flex';
  }

  function createPasskeyItem(passkey: any): HTMLElement {
    const div = document.createElement('div');
    div.className = 'passkey-item';

    const createdAt = passkey.createdAt ? new Date(passkey.createdAt) : null;
    const dateStr = createdAt
      ? createdAt.toLocaleDateString() +
        ' ' +
        createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : 'Unknown';

    const credentialIdShort = passkey.id ? passkey.id.substring(0, 20) + '...' : 'Unknown';

    div.innerHTML = `
      <div class="passkey-header">
        <div class="passkey-info">
          <div class="passkey-rp">${popupEscapeHtml(passkey.rpId || 'Unknown Site')}</div>
          ${passkey.user?.name ? `<div class="passkey-username">${popupEscapeHtml(passkey.user.name)}</div>` : ''}
        </div>
        <div class="passkey-actions">
          <button class="copy-btn" title="Copy to clipboard">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2"></rect>
              <rect x="3" y="3" width="13" height="13" rx="2"></rect>
            </svg>
          </button>
          <button class="expand-btn" title="Details">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </button>
          <button class="delete-btn" data-id="${popupEscapeHtml(passkey.id)}">Del</button>
        </div>
      </div>
      <div class="passkey-details">
        <div class="passkey-detail-row">
          <span class="label">Added:</span>
          <span class="value">${popupEscapeHtml(dateStr)}</span>
        </div>
        <div class="passkey-detail-row">
          <span class="label">Key ID:</span>
          <span class="value">${popupEscapeHtml(credentialIdShort)}</span>
        </div>
      </div>
    `;

    const copyBtn = div.querySelector('.copy-btn') as HTMLButtonElement;
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyPasskeyToClipboard(passkey, copyBtn);
    });

    const expandBtn = div.querySelector('.expand-btn') as HTMLButtonElement;
    const details = div.querySelector('.passkey-details') as HTMLElement;
    expandBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isExpanded = details.classList.toggle('show');
      expandBtn.classList.toggle('expanded', isExpanded);
      div.classList.toggle('expanded', isExpanded);
    });

    const deleteBtn = div.querySelector('.delete-btn') as HTMLButtonElement;
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deletePasskey(passkey.id, passkey.rpId || 'this site');
    });

    return div;
  }

  async function copyPasskeyToClipboard(passkey: any, btn: HTMLButtonElement): Promise<void> {
    const debugData = {
      id: passkey.id,
      credentialId: passkey.credentialId,
      type: passkey.type,
      rpId: passkey.rpId,
      origin: passkey.origin,
      user: passkey.user,
      publicKey: passkey.publicKey,
      createdAt: passkey.createdAt,
      counter: passkey.counter,
      lastUsed: passkey.lastUsed,
    };

    try {
      await navigator.clipboard.writeText(JSON.stringify(debugData, null, 2));
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      showNotification('Failed to copy', 'error');
    }
  }

  async function deletePasskey(credentialId: string, siteName: string): Promise<void> {
    const confirmed = await showConfirmModal(
      'Delete Passkey?',
      `You will no longer be able to sign in to ${siteName} using this passkey.`,
      'Delete',
      true
    );

    if (!confirmed) return;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'DELETE_PASSKEY',
        payload: { credentialId },
      });

      if (response?.success) {
        showNotification('Passkey deleted successfully');
        await loadPasskeys();
      } else if (!response || response?.requiresSetup) {
        showSetupPanel();
      } else if (response?.requiresUnlock) {
        showUnlockPanel();
      } else {
        showNotification(response?.error || 'Failed to delete passkey', 'error');
      }
    } catch (error) {
      console.error('Error deleting passkey:', error);
      showNotification('Failed to delete passkey', 'error');
    }
  }

  async function clearAllPasskeys(): Promise<void> {
    const passkeyCount = allPasskeys.length;

    if (passkeyCount === 0) {
      showNotification('No passkeys to clear', 'error');
      return;
    }

    const confirmed = await showConfirmModal(
      `Delete All ${passkeyCount} Passkeys?`,
      'This will permanently remove all your passkeys. You will lose access to any accounts that only have passkey authentication.',
      'Delete All',
      true
    );

    if (!confirmed) return;

    try {
      const response = await chrome.runtime.sendMessage({ type: 'CLEAR_PASSKEYS', payload: {} });

      if (response?.success) {
        showNotification('All passkeys cleared');
        await loadPasskeys();
      } else if (!response || response?.requiresSetup) {
        showSetupPanel();
      } else if (response?.requiresUnlock) {
        showUnlockPanel();
      } else {
        showNotification(response?.error || 'Failed to clear passkeys', 'error');
      }
    } catch (error) {
      console.error('Error clearing passkeys:', error);
      showNotification('Failed to clear passkeys', 'error');
    }
  }

  async function exportPasskeysFull(): Promise<void> {
    const confirmed = await showConfirmModal(
      'Export Full Backup?',
      'This will export ALL passkey data including private keys. Keep this file secure and never share it with anyone!',
      'Export Full Backup',
      false
    );

    if (!confirmed) return;

    try {
      const response = await chrome.runtime.sendMessage({ type: 'LIST_PASSKEYS', payload: {} });

      if (!response || response?.requiresSetup) {
        showSetupPanel();
        return;
      }
      if (response?.requiresUnlock) {
        showUnlockPanel();
        return;
      }

      const passkeys: any[] = response?.passkeys || [];

      if (passkeys.length === 0) {
        showNotification('No passkeys to export', 'error');
        return;
      }

      const exportData = {
        version: EXPORT_VERSION,
        exportType: 'full',
        exportedAt: new Date().toISOString(),
        description: 'PassKey Vault FULL backup (contains private keys - KEEP SECURE!)',
        passkeys: passkeys.map((p) => ({
          id: p.id,
          credentialId: p.credentialId,
          type: p.type,
          rpId: p.rpId,
          origin: p.origin,
          user: p.user,
          privateKey: p.privateKey,
          publicKey: p.publicKey,
          createdAt: p.createdAt,
          counter: p.counter,
          lastUsed: p.lastUsed,
          prfKey: p.prfKey,
        })),
      };

      downloadJson(exportData, `passkeys-FULL-BACKUP-${getDateString()}.json`);
      showNotification(`Exported ${passkeys.length} passkeys (full backup)`);
    } catch (error) {
      console.error('Error exporting passkeys:', error);
      showNotification('Failed to export passkeys', 'error');
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────────

  function downloadJson(data: any, filename: string): void {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function getDateString(): string {
    return new Date().toISOString().split('T')[0];
  }

  function showNotification(message: string, type: string = 'success'): void {
    const existing = document.querySelector('.popup-notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `popup-notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      padding: 10px 16px;
      background: ${type === 'success' ? '#10b981' : '#ef4444'};
      color: white;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      z-index: 3000;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      animation: slideDown 0.3s ease-out;
      max-width: 90%;
      text-align: center;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideUp 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, 2500);
  }

  function popupEscapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
})();
