<script setup>
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'
import api from './api'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

// After a brokered login the callback redirects with #broker_token=... in the
// fragment; pick it up, persist it and load the user.
const hashMatch = window.location.hash.match(/broker_token=([^&]+)/)
if (hashMatch) {
  auth.accessToken = hashMatch[1]
  localStorage.setItem('sso_access_token', hashMatch[1])
  history.replaceState(null, '', window.location.pathname + window.location.search)
  api.get('/api/v1/auth/me').then(({ data }) => {
    auth.user = data
    localStorage.setItem('sso_user', JSON.stringify(data))
  }).catch(() => {})
}

async function signOut() {
  await auth.logout()
  router.push('/login')
}
</script>

<template>
  <nav v-if="auth.isAuthenticated && !route.meta.public" class="navbar navbar-expand navbar-dark bg-dark px-3">
    <router-link class="navbar-brand" to="/">SSO Admin</router-link>
    <div class="navbar-nav me-auto">
      <router-link class="nav-link" to="/users">Users</router-link>
      <router-link class="nav-link" to="/roles">Roles</router-link>
      <router-link class="nav-link" to="/groups">Groups</router-link>
      <router-link class="nav-link" to="/clients">OAuth Clients</router-link>
      <router-link class="nav-link" to="/ldap">LDAP</router-link>
      <router-link class="nav-link" to="/identity-providers">Federation</router-link>
      <router-link class="nav-link" to="/audit">Audit</router-link>
    </div>
    <router-link class="navbar-text me-3 text-decoration-none" to="/account">{{ auth.user?.username }}</router-link>
    <button class="btn btn-outline-light btn-sm" @click="signOut">Sign out</button>
  </nav>
  <main class="container py-4">
    <router-view />
  </main>
</template>
