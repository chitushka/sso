<script setup>
import { onMounted, ref } from 'vue'
import api from '../api'

const counts = ref({ users: null, roles: null, clients: null, providers: null })
const health = ref('unknown')

onMounted(async () => {
  try {
    const [users, roles, clients, providers] = await Promise.all([
      api.get('/api/v1/users?limit=100'),
      api.get('/api/v1/roles'),
      api.get('/api/v1/oauth/clients'),
      api.get('/api/v1/ldap/providers')
    ])
    counts.value = {
      users: users.data.length,
      roles: roles.data.length,
      clients: clients.data.length,
      providers: providers.data.length
    }
  } catch {
    /* individual cards just stay empty */
  }
  try {
    await api.get('/health/ready')
    health.value = 'ready'
  } catch {
    health.value = 'not ready'
  }
})

const cards = [
  { to: '/users', title: 'Users', key: 'users' },
  { to: '/roles', title: 'Roles', key: 'roles' },
  { to: '/clients', title: 'OAuth Clients', key: 'clients' },
  { to: '/ldap', title: 'LDAP Providers', key: 'providers' }
]
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h3 class="mb-0">Dashboard</h3>
    <span class="badge" :class="health === 'ready' ? 'bg-success' : 'bg-danger'">API {{ health }}</span>
  </div>
  <div class="row g-3">
    <div v-for="c in cards" :key="c.to" class="col-md-3">
      <router-link :to="c.to" class="text-decoration-none">
        <div class="card text-center shadow-sm h-100">
          <div class="card-body">
            <div class="display-6">{{ counts[c.key] ?? '—' }}</div>
            <div class="text-muted">{{ c.title }}</div>
          </div>
        </div>
      </router-link>
    </div>
  </div>
</template>
