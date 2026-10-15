<script setup>
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const appVersion = import.meta.env.VITE_APP_VERSION || 'dev'

async function signOut() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <nav v-if="auth.isAuthenticated && !route.meta.public" class="navbar navbar-expand navbar-dark bg-dark px-3">
    <router-link class="navbar-brand" to="/">{{ $t('app.title') }} <small class="text-secondary">{{ appVersion }}</small></router-link>
    <div class="navbar-nav me-auto">
      <router-link class="nav-link" to="/users">{{ $t('app.users') }}</router-link>
      <router-link class="nav-link" to="/roles">{{ $t('app.roles') }}</router-link>
      <router-link class="nav-link" to="/groups">{{ $t('app.groups') }}</router-link>
      <router-link class="nav-link" to="/clients">{{ $t('app.clients') }}</router-link>
      <router-link class="nav-link" to="/ldap">{{ $t('app.ldap') }}</router-link>
      <router-link class="nav-link" to="/identity-providers">{{ $t('app.federation') }}</router-link>
      <router-link class="nav-link" to="/audit">{{ $t('app.audit') }}</router-link>
    </div>
    <router-link class="navbar-text me-3 text-decoration-none" to="/account">{{ auth.user?.username }}</router-link>
    <button class="btn btn-outline-light btn-sm" @click="signOut">{{ $t('app.signOut') }}</button>
  </nav>
  <main class="container py-4">
    <router-view />
  </main>
</template>
