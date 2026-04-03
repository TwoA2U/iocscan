import {
    currentUser,
    goToScanner,
    logout,
    changePassword,
    loadMaskedKeys,
    saveKeys,
} from '../composables/useAuth.js?v=12';

import { resetScanState } from '../composables/useIOCScan.js?v=12';

const { defineComponent, ref, reactive, onMounted } = Vue;

export default defineComponent({
    name: 'SettingsPage',
    props: {
        forced: { type: Boolean, default: false },
    },

    setup(props) {
        const passwordForm = reactive({
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
        });
        const keyForm = reactive({
            vtKey: '',
            abuseKey: '',
            ipapiKey: '',
            abusechKey: '',
            greynoiseKey: '',
        });
        const showPasswords = reactive({
            current: false,
            next: false,
            confirm: false,
        });
        const maskedKeys = ref({
            vtKey: '',
            abuseKey: '',
            ipapiKey: '',
            abusechKey: '',
            greynoiseKey: '',
        });
        const pwError = ref('');
        const pwSuccess = ref('');
        const keysError = ref('');
        const keysSuccess = ref('');
        const loadingKeys = ref(false);
        const savingKeys = ref(false);
        const changingPw = ref(false);

        async function refreshKeys() {
            loadingKeys.value = true;
            keysError.value = '';
            try {
                maskedKeys.value = await loadMaskedKeys();
            } catch (err) {
                keysError.value = err.message || 'Failed to load keys.';
            } finally {
                loadingKeys.value = false;
            }
        }

        async function submitPassword() {
            pwError.value = '';
            pwSuccess.value = '';
            if (!passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword) {
                pwError.value = 'All password fields are required.';
                return;
            }
            if (passwordForm.newPassword.length < 8) {
                pwError.value = 'New password must be at least 8 characters.';
                return;
            }
            if (passwordForm.newPassword !== passwordForm.confirmPassword) {
                pwError.value = 'New password and confirmation do not match.';
                return;
            }

            changingPw.value = true;
            try {
                await changePassword(passwordForm.currentPassword, passwordForm.newPassword);
                passwordForm.currentPassword = '';
                passwordForm.newPassword = '';
                passwordForm.confirmPassword = '';
                pwSuccess.value = 'Password updated.';
            } catch (err) {
                pwError.value = err.message || 'Failed to update password.';
            } finally {
                changingPw.value = false;
            }
        }

        async function submitKeys() {
            keysError.value = '';
            keysSuccess.value = '';
            const payload = {};
            for (const [key, value] of Object.entries(keyForm)) {
                if (value.trim()) payload[key] = value.trim();
            }
            if (!Object.keys(payload).length) {
                keysError.value = 'Enter at least one new key value to save.';
                return;
            }

            savingKeys.value = true;
            try {
                await saveKeys(payload);
                Object.keys(keyForm).forEach(k => { keyForm[k] = ''; });
                keysSuccess.value = 'Keys saved.';
                await refreshKeys();
            } catch (err) {
                keysError.value = err.message || 'Failed to save keys.';
            } finally {
                savingKeys.value = false;
            }
        }

        async function logoutNow() {
            resetScanState();
            await logout();
        }

        onMounted(() => {
            if (!props.forced) {
                refreshKeys();
            }
        });

        return {
            currentUser,
            passwordForm,
            keyForm,
            showPasswords,
            maskedKeys,
            pwError,
            pwSuccess,
            keysError,
            keysSuccess,
            loadingKeys,
            savingKeys,
            changingPw,
            submitPassword,
            submitKeys,
            logoutNow,
            goToScanner,
            forced: props.forced,
        };
    },

    template: `
    <div class="min-h-screen bg-ink text-t1 px-6 py-8">
      <div class="max-w-5xl mx-auto">
        <div class="flex items-center justify-between gap-4 mb-6">
          <div>
            <div class="font-display font-bold text-2xl">Settings</div>
            <div class="text-xs tracking-[0.18em] uppercase text-t3 mt-1">
              {{ forced ? 'Password change required before scanning' : 'Account and API key management' }}
            </div>
          </div>
          <div class="flex items-center gap-2">
            <button v-if="!forced" class="act-btn" @click="goToScanner">Back To Scanner</button>
            <button class="act-btn" @click="logoutNow">Logout</button>
          </div>
        </div>

        <div class="grid gap-6 lg:grid-cols-2">
          <div class="vcard p-5">
            <div class="vcard-title mb-4">Account</div>
            <div class="text-sm text-t2 mb-4">
              Signed in as <span class="font-mono text-t1">{{ currentUser ? currentUser.username : '' }}</span>
            </div>
            <div v-if="pwError" class="err-box mb-4">⚠ {{ pwError }}</div>
            <div v-if="pwSuccess" class="text-sm text-rk border border-rk/20 bg-rk/10 rounded-md px-3 py-2 mb-4">{{ pwSuccess }}</div>
            <div class="space-y-4">
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Current Password</label>
                <div class="pw-field">
                  <input v-model="passwordForm.currentPassword" :type="showPasswords.current ? 'text' : 'password'" class="key-input pw-input">
                  <button type="button" class="pw-toggle" :aria-label="showPasswords.current ? 'Hide password' : 'Show password'" :title="showPasswords.current ? 'Hide password' : 'Show password'" @click="showPasswords.current = !showPasswords.current">
                    <svg v-if="!showPasswords.current" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/>
                    </svg>
                    <svg v-else class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M3 3l18 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                      <path d="M10.6 5.2A11.4 11.4 0 0 1 12 5c6.5 0 10 7 10 7a18.7 18.7 0 0 1-4.1 4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M6.7 6.7C3.8 8.5 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M9.9 9.9A3 3 0 0 0 14.1 14.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">New Password</label>
                <div class="pw-field">
                  <input v-model="passwordForm.newPassword" :type="showPasswords.next ? 'text' : 'password'" class="key-input pw-input">
                  <button type="button" class="pw-toggle" :aria-label="showPasswords.next ? 'Hide password' : 'Show password'" :title="showPasswords.next ? 'Hide password' : 'Show password'" @click="showPasswords.next = !showPasswords.next">
                    <svg v-if="!showPasswords.next" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/>
                    </svg>
                    <svg v-else class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M3 3l18 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                      <path d="M10.6 5.2A11.4 11.4 0 0 1 12 5c6.5 0 10 7 10 7a18.7 18.7 0 0 1-4.1 4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M6.7 6.7C3.8 8.5 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M9.9 9.9A3 3 0 0 0 14.1 14.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Confirm New Password</label>
                <div class="pw-field">
                  <input v-model="passwordForm.confirmPassword" :type="showPasswords.confirm ? 'text' : 'password'" class="key-input pw-input">
                  <button type="button" class="pw-toggle" :aria-label="showPasswords.confirm ? 'Hide password' : 'Show password'" :title="showPasswords.confirm ? 'Hide password' : 'Show password'" @click="showPasswords.confirm = !showPasswords.confirm">
                    <svg v-if="!showPasswords.confirm" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/>
                    </svg>
                    <svg v-else class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path d="M3 3l18 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                      <path d="M10.6 5.2A11.4 11.4 0 0 1 12 5c6.5 0 10 7 10 7a18.7 18.7 0 0 1-4.1 4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M6.7 6.7C3.8 8.5 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                      <path d="M9.9 9.9A3 3 0 0 0 14.1 14.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                    </svg>
                  </button>
                </div>
              </div>
              <button class="scan-btn h-[44px] w-full" :disabled="changingPw" @click="submitPassword">
                <span v-if="!changingPw">CHANGE PASSWORD</span>
                <span v-else class="flex items-center justify-center gap-2"><span class="loader"></span> Updating</span>
              </button>
            </div>
          </div>

          <div v-if="!forced" class="vcard p-5">
            <div class="vcard-title mb-4">API Keys</div>
            <div v-if="keysError" class="err-box mb-4">⚠ {{ keysError }}</div>
            <div v-if="keysSuccess" class="text-sm text-rk border border-rk/20 bg-rk/10 rounded-md px-3 py-2 mb-4">{{ keysSuccess }}</div>
            <div class="space-y-4">
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">VirusTotal</label>
                <input v-model="keyForm.vtKey" class="key-input" :placeholder="loadingKeys ? 'Loading…' : (maskedKeys.vtKey || 'Not set')">
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">AbuseIPDB</label>
                <input v-model="keyForm.abuseKey" class="key-input" :placeholder="loadingKeys ? 'Loading…' : (maskedKeys.abuseKey || 'Not set')">
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">ipapi.is</label>
                <input v-model="keyForm.ipapiKey" class="key-input" :placeholder="loadingKeys ? 'Loading…' : (maskedKeys.ipapiKey || 'Not set')">
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">abuse.ch (ThreatFox / MalwareBazaar)</label>
                <input v-model="keyForm.abusechKey" class="key-input" :placeholder="loadingKeys ? 'Loading…' : (maskedKeys.abusechKey || 'Not set')">
              </div>
              <div>
                <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">GreyNoise</label>
                <input v-model="keyForm.greynoiseKey" class="key-input" :placeholder="loadingKeys ? 'Loading…' : (maskedKeys.greynoiseKey || 'Not set')">
              </div>
              <button class="scan-btn h-[44px] w-full" :disabled="savingKeys || loadingKeys" @click="submitKeys">
                <span v-if="!savingKeys">SAVE KEYS</span>
                <span v-else class="flex items-center justify-center gap-2"><span class="loader"></span> Saving</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    `,
});
