import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'
import LoginView from './views/LoginView.vue'
import DashboardView from './views/DashboardView.vue'
import UsersView from './views/UsersView.vue'
import RolesView from './views/RolesView.vue'
import GroupsView from './views/GroupsView.vue'
import ClientsView from './views/ClientsView.vue'
import LdapView from './views/LdapView.vue'
import AuditView from './views/AuditView.vue'
import ConsentView from './views/ConsentView.vue'
import AccountView from './views/AccountView.vue'
import ForgotPasswordView from './views/ForgotPasswordView.vue'
import ResetPasswordView from './views/ResetPasswordView.vue'
import VerifyEmailView from './views/VerifyEmailView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: LoginView, meta: { public: true } },
    { path: '/consent', component: ConsentView, meta: { public: true } },
    { path: '/forgot-password', component: ForgotPasswordView, meta: { public: true } },
    { path: '/reset-password', component: ResetPasswordView, meta: { public: true } },
    { path: '/verify-email', component: VerifyEmailView, meta: { public: true } },
    { path: '/', component: DashboardView },
    { path: '/users', component: UsersView },
    { path: '/roles', component: RolesView },
    { path: '/groups', component: GroupsView },
    { path: '/clients', component: ClientsView },
    { path: '/ldap', component: LdapView },
    { path: '/audit', component: AuditView },
    { path: '/account', component: AccountView }
  ]
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isAuthenticated) {
    return { path: '/login', query: { continue: to.fullPath } }
  }
})

export default router
