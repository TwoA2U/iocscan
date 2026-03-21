import IOCScanner from './IOCScanner.js';
import LoginPage from './LoginPage.js';
import SettingsPage from './SettingsPage.js';
import AdminPage from './AdminPage.js';

import {
    authReady,
    currentUser,
    currentPage,
    mustChangePw,
    checkSession,
} from '../composables/useAuth.js';

const { defineComponent, computed, onMounted, h } = Vue;

export default defineComponent({
    name: 'AppShell',

    setup() {
        onMounted(() => {
            checkSession();
        });

        const activeView = computed(() => {
            if (!authReady.value) return 'loading';
            if (!currentUser.value) return 'login';
            if (mustChangePw.value) return 'settings';
            if (currentPage.value === 'admin') return 'admin';
            if (currentPage.value === 'settings') return 'settings';
            return 'scanner';
        });

        return {
            activeView,
            mustChangePw,
            renderView() {
                if (activeView.value === 'loading') {
                    return h(
                        'div',
                        { class: 'min-h-screen bg-ink text-t1 flex items-center justify-center' },
                        [
                            h('div', { class: 'flex items-center gap-3 text-sm tracking-widest uppercase text-t2' }, [
                                h('span', { class: 'loader' }),
                                'Loading Session',
                            ]),
                        ]
                    );
                }

                if (activeView.value === 'login') {
                    return h(LoginPage);
                }

                if (activeView.value === 'settings') {
                    return h(SettingsPage, { forced: mustChangePw.value });
                }

                if (activeView.value === 'admin') {
                    return h(AdminPage);
                }

                return h(IOCScanner);
            },
        };
    },

    render() {
        return this.renderView();
    },
});
