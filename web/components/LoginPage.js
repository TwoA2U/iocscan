import {
    login,
    authError,
} from '../composables/useAuth.js';

const { defineComponent, ref } = Vue;

export default defineComponent({
    name: 'LoginPage',

    setup() {
        const username = ref('');
        const password = ref('');
        const showPassword = ref(false);
        const error = ref('');
        const submitting = ref(false);

        async function submit() {
            error.value = '';
            if (!username.value.trim() || !password.value) {
                error.value = 'Username and password are required.';
                return;
            }

            submitting.value = true;
            try {
                await login(username.value.trim(), password.value);
            } catch (err) {
                error.value = err.message || 'Login failed.';
            } finally {
                submitting.value = false;
            }
        }

        return {
            username,
            password,
            showPassword,
            error,
            authError,
            submitting,
            submit,
        };
    },

    template: `
    <div class="min-h-screen bg-ink text-t1 flex items-center justify-center px-6">
      <div class="w-full max-w-md border border-white/10 bg-ink1 rounded-lg shadow-card p-6">
        <div class="mb-6">
          <div class="font-display font-bold text-3xl tracking-tight">
            <span class="text-t1">ioc</span><span class="text-prime">scan</span>
          </div>
          <div class="text-xs tracking-[0.22em] uppercase text-t3 mt-2">Sign In</div>
        </div>

        <div v-if="error || authError" class="err-box mb-4">
          ⚠ {{ error || authError }}
        </div>

        <div class="space-y-4">
          <div>
            <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Username</label>
            <input v-model="username" class="key-input" autocomplete="username" @keydown.enter.prevent="submit">
          </div>
          <div>
            <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Password</label>
            <div class="pw-field">
              <input v-model="password" :type="showPassword ? 'text' : 'password'" class="key-input pw-input" autocomplete="current-password" @keydown.enter.prevent="submit">
              <button type="button" class="pw-toggle" :aria-label="showPassword ? 'Hide password' : 'Show password'" :title="showPassword ? 'Hide password' : 'Show password'" @click="showPassword = !showPassword">
                <svg v-if="!showPassword" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
          <button class="scan-btn h-[46px] w-full" :disabled="submitting" @click="submit">
            <span v-if="!submitting">LOGIN</span>
            <span v-else class="flex items-center justify-center gap-2"><span class="loader"></span> Signing In</span>
          </button>
        </div>
      </div>
    </div>
    `,
});
