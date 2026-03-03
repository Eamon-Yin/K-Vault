import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '../stores/auth';
import AppShell from '../components/AppShell.vue';
import LoginView from '../views/LoginView.vue';
import UploadView from '../views/UploadView.vue';
import DriveView from '../views/DriveView.vue';
import StorageView from '../views/StorageView.vue';

const routes = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { public: true },
  },
  {
    path: '/',
    component: AppShell,
    children: [
      { path: '', redirect: '/upload' },
      { path: 'upload', name: 'upload', component: UploadView },
      { path: 'drive', name: 'drive', component: DriveView, meta: { requiresAdmin: true } },
      { path: 'admin', redirect: '/drive' },
      { path: 'storage', name: 'storage', component: StorageView, meta: { requiresAdmin: true } },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/upload' },
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

router.beforeEach(async (to) => {
  const authStore = useAuthStore();
  if (!authStore.initialized) {
    await authStore.refresh();
  }

  if (to.name === 'login') {
    if (!authStore.authRequired || authStore.authenticated) {
      const target = typeof to.query.redirect === 'string' ? to.query.redirect : '/upload';
      return target;
    }
    return true;
  }

  if (to.meta.requiresAdmin && authStore.authRequired && !authStore.authenticated) {
    return {
      name: 'login',
      query: { redirect: to.fullPath },
    };
  }

  return true;
});

export default router;
