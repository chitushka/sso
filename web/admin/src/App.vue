<script setup>
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

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
      <router-link class="nav-link" to="/audit">Audit</router-link>
    </div>
    <router-link class="navbar-text me-3 text-decoration-none" to="/account">{{ auth.user?.username }}</router-link>
    <button class="btn btn-outline-light btn-sm" @click="signOut">Sign out</button>
  </nav>
  <main class="container py-4">
    <router-view />
  </main>
</template>
