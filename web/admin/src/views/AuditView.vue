<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const events = ref([])
const error = ref('')
const filters = ref({ action: '', from: '', to: '', limit: 50 })

async function load() {
  error.value = ''
  const params = { limit: filters.value.limit }
  if (filters.value.action) params.action = filters.value.action
  if (filters.value.from) params.from = new Date(filters.value.from).toISOString()
  if (filters.value.to) params.to = new Date(filters.value.to).toISOString()
  try {
    const { data } = await api.get('/api/v1/audit', { params })
    events.value = data
  } catch (e) {
    error.value = apiError(e)
  }
}
onMounted(load)
</script>

<template>
  <h3 class="mb-3">Audit Log</h3>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <form class="row g-2 mb-3" @submit.prevent="load">
    <div class="col-md-3"><input v-model="filters.action" class="form-control" placeholder="action (e.g. login_failed)" /></div>
    <div class="col-md-3"><input v-model="filters.from" type="datetime-local" class="form-control" /></div>
    <div class="col-md-3"><input v-model="filters.to" type="datetime-local" class="form-control" /></div>
    <div class="col-md-1">
      <select v-model.number="filters.limit" class="form-select">
        <option :value="50">50</option>
        <option :value="100">100</option>
        <option :value="200">200</option>
      </select>
    </div>
    <div class="col-md-2"><button class="btn btn-primary w-100">Filter</button></div>
  </form>

  <table class="table table-sm table-hover align-middle">
    <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Actor</th><th>IP</th></tr></thead>
    <tbody>
      <tr v-for="e in events" :key="e.id">
        <td class="text-muted small">{{ new Date(e.created_at).toLocaleString() }}</td>
        <td><span class="badge bg-light text-dark">{{ e.action }}</span></td>
        <td class="small">{{ e.target_type }}<span v-if="e.target_id" class="text-muted"> / {{ e.target_id }}</span></td>
        <td class="small text-muted">{{ e.actor_user_id || '—' }}</td>
        <td class="small text-muted">{{ e.ip }}</td>
      </tr>
    </tbody>
  </table>
  <p v-if="!events.length" class="text-muted">No events.</p>
</template>
