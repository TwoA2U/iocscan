import {
    currentUser,
    goToScanner,
    logout,
    isAdmin,
} from '../composables/useAuth.js';

import { apiFetch } from '../composables/useAuth.js';
import { resetScanState } from '../composables/useIOCScan.js';

const { defineComponent, ref, reactive, onMounted } = Vue;

export default defineComponent({
    name: 'AdminPage',

    setup() {
        const users = ref([]);
        const loading = ref(false);
        const error = ref('');
        const success = ref('');
        const createForm = reactive({
            username: '',
            password: '',
            isAdmin: false,
        });
        const resetMap = reactive({});
        const showCreatePassword = ref(false);
        const resetShowMap = reactive({});

        async function loadUsers() {
            loading.value = true;
            error.value = '';
            try {
                users.value = await apiFetch('/api/admin/users');
            } catch (err) {
                error.value = err.message || 'Failed to load users.';
            } finally {
                loading.value = false;
            }
        }

        async function createUser() {
            error.value = '';
            success.value = '';
            if (!createForm.username.trim() || !createForm.password) {
                error.value = 'Username and password are required.';
                return;
            }
            if (createForm.password.length < 8) {
                error.value = 'Password must be at least 8 characters.';
                return;
            }
            try {
                await apiFetch('/api/admin/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: createForm.username.trim(),
                        password: createForm.password,
                        isAdmin: createForm.isAdmin,
                    }),
                });
                createForm.username = '';
                createForm.password = '';
                createForm.isAdmin = false;
                success.value = 'User created.';
                await loadUsers();
            } catch (err) {
                error.value = err.message || 'Failed to create user.';
            }
        }

        async function deleteUser(user) {
            error.value = '';
            success.value = '';
            if (!confirm(`Delete user "${user.username}"?`)) return;
            try {
                await apiFetch(`/api/admin/users/${user.id}`, { method: 'DELETE' });
                success.value = 'User deleted.';
                await loadUsers();
            } catch (err) {
                error.value = err.message || 'Failed to delete user.';
            }
        }

        async function resetPassword(user) {
            error.value = '';
            success.value = '';
            const newPassword = (resetMap[user.id] || '').trim();
            if (newPassword.length < 8) {
                error.value = 'Reset password must be at least 8 characters.';
                return;
            }
            try {
                await apiFetch(`/api/admin/users/${user.id}/password`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newPassword }),
                });
                resetMap[user.id] = '';
                success.value = `Password reset for ${user.username}.`;
                await loadUsers();
            } catch (err) {
                error.value = err.message || 'Failed to reset password.';
            }
        }

        async function logoutNow() {
            resetScanState();
            await logout();
        }

        onMounted(() => {
            loadUsers();
        });

        return {
            currentUser,
            isAdmin,
            users,
            loading,
            error,
            success,
            createForm,
            resetMap,
            showCreatePassword,
            resetShowMap,
            loadUsers,
            createUser,
            deleteUser,
            resetPassword,
            goToScanner,
            logoutNow,
        };
    },

    template: `
    <div class="min-h-screen bg-ink text-t1 px-6 py-8">
      <div class="max-w-6xl mx-auto">
        <div class="flex items-center justify-between gap-4 mb-6">
          <div>
            <div class="font-display font-bold text-2xl">Admin</div>
            <div class="text-xs tracking-[0.18em] uppercase text-t3 mt-1">User Management</div>
          </div>
          <div class="flex items-center gap-2">
            <button class="act-btn" @click="goToScanner">Back To Scanner</button>
            <button class="act-btn" @click="logoutNow">Logout</button>
          </div>
        </div>

        <div v-if="!isAdmin" class="err-box">⚠ Admin access required.</div>

        <template v-else>
          <div v-if="error" class="err-box mb-4">⚠ {{ error }}</div>
          <div v-if="success" class="text-sm text-rk border border-rk/20 bg-rk/10 rounded-md px-3 py-2 mb-4">{{ success }}</div>

          <div class="grid gap-6 lg:grid-cols-[320px,1fr]">
            <div class="vcard p-5">
              <div class="vcard-title mb-4">Create User</div>
              <div class="space-y-4">
                <div>
                  <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Username</label>
                  <input v-model="createForm.username" class="key-input">
                </div>
                <div>
                  <label class="block text-xs font-semibold tracking-wider uppercase text-t3 mb-1.5">Temporary Password</label>
                  <div class="pw-field">
                    <input v-model="createForm.password" :type="showCreatePassword ? 'text' : 'password'" class="key-input pw-input">
                    <button type="button" class="pw-toggle" :aria-label="showCreatePassword ? 'Hide password' : 'Show password'" :title="showCreatePassword ? 'Hide password' : 'Show password'" @click="showCreatePassword = !showCreatePassword">
                      <svg v-if="!showCreatePassword" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
                <label class="flex items-center gap-3 text-sm text-t2">
                  <input v-model="createForm.isAdmin" type="checkbox">
                  Admin User
                </label>
                <button class="scan-btn h-[44px] w-full" @click="createUser">CREATE USER</button>
              </div>
            </div>

            <div class="vcard p-5">
              <div class="flex items-center justify-between gap-3 mb-4">
                <div class="vcard-title">Users</div>
                <button class="act-btn" :disabled="loading" @click="loadUsers">Refresh</button>
              </div>
              <div v-if="loading" class="flex items-center gap-3 text-sm text-t2"><span class="loader"></span> Loading users</div>
              <div v-else class="overflow-x-auto">
                <table class="ioc-table">
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Role</th>
                      <th>Must Change</th>
                      <th>Created</th>
                      <th>Reset Password</th>
                      <th>Delete</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="user in users" :key="user.id">
                      <td>{{ user.username }}</td>
                      <td>{{ user.isAdmin ? 'Admin' : 'User' }}</td>
                      <td>{{ user.mustChangePw ? 'Yes' : 'No' }}</td>
                      <td>{{ user.createdAt }}</td>
                      <td>
                        <div class="flex items-center gap-2">
                          <div class="pw-field" style="min-width:180px">
                            <input v-model="resetMap[user.id]" :type="resetShowMap[user.id] ? 'text' : 'password'" class="key-input pw-input" placeholder="New password">
                            <button type="button" class="pw-toggle" :aria-label="resetShowMap[user.id] ? 'Hide password' : 'Show password'" :title="resetShowMap[user.id] ? 'Hide password' : 'Show password'" @click="resetShowMap[user.id] = !resetShowMap[user.id]">
                              <svg v-if="!resetShowMap[user.id]" class="pw-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
                          <button class="act-btn" @click.stop="resetPassword(user)">Reset</button>
                        </div>
                      </td>
                      <td>
                        <button class="act-btn" @click.stop="deleteUser(user)">Delete</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>
    `,
});
