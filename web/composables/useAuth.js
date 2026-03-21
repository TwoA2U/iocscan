const { ref, computed } = Vue;

export const currentUser = ref(null);
export const authReady = ref(false);
export const authError = ref('');
export const currentPage = ref('scanner');

export const isLoggedIn = computed(() => !!currentUser.value);
export const isAdmin = computed(() => !!currentUser.value?.isAdmin);
export const mustChangePw = computed(() => !!currentUser.value?.mustChangePw);

export function navigateTo(page) {
    currentPage.value = page;
}

export function goToScanner() {
    currentPage.value = 'scanner';
}

export function goToSettings() {
    currentPage.value = 'settings';
}

export function goToAdmin() {
    currentPage.value = 'admin';
}

function clearAuthState() {
    currentUser.value = null;
    authError.value = '';
    currentPage.value = 'scanner';
}

async function parseResponseBody(res) {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return res.json();
    }
    const text = await res.text();
    return text ? { error: text } : {};
}

export async function apiFetch(url, options = {}) {
    const {
        suppressAuthRedirect = false,
        headers,
        ...rest
    } = options;

    const res = await fetch(url, {
        credentials: 'same-origin',
        ...rest,
        headers: {
            ...(headers || {}),
        },
    });

    const data = await parseResponseBody(res);

    if (res.status === 401 && !suppressAuthRedirect) {
        clearAuthState();
        authReady.value = true;
        throw new Error(data.error || 'unauthorized');
    }

    if (res.status === 403 && data?.error === 'password_change_required' && !suppressAuthRedirect) {
        if (currentUser.value) {
            currentUser.value = { ...currentUser.value, mustChangePw: true };
        }
        currentPage.value = 'settings';
        throw new Error(data.error);
    }

    if (!res.ok) {
        throw new Error(data?.error || `HTTP ${res.status}`);
    }

    return data;
}

export async function checkSession() {
    authError.value = '';
    try {
        const data = await apiFetch('/auth/me', { suppressAuthRedirect: true });
        currentUser.value = data?.user || null;
        currentPage.value = currentUser.value?.mustChangePw ? 'settings' : 'scanner';
    } catch (err) {
        clearAuthState();
        authError.value = err.message;
    } finally {
        authReady.value = true;
    }
}

export async function login(username, password) {
    authError.value = '';
    const data = await apiFetch('/auth/login', {
        suppressAuthRedirect: true,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });
    currentUser.value = data || null;
    currentPage.value = currentUser.value?.mustChangePw ? 'settings' : 'scanner';
    return data;
}

export async function logout() {
    try {
        await apiFetch('/auth/logout', {
            suppressAuthRedirect: true,
            method: 'POST',
        });
    } finally {
        clearAuthState();
        authReady.value = true;
    }
}

export async function changePassword(currentPassword, newPassword) {
    const data = await apiFetch('/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword }),
    });
    if (currentUser.value) {
        currentUser.value = { ...currentUser.value, mustChangePw: false };
    }
    currentPage.value = 'scanner';
    return data;
}

export async function loadMaskedKeys() {
    return apiFetch('/api/keys', { method: 'GET' });
}

export async function saveKeys(payload) {
    return apiFetch('/api/keys', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
}
