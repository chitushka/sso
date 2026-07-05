<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api from '../api'

const route = useRoute()
const state = ref('working') // working | ok | failed

onMounted(async () => {
  try {
    await api.post('/api/v1/auth/email/verify', { token: String(route.query.token || '') })
    state.value = 'ok'
  } catch {
    state.value = 'failed'
  }
})
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-4 text-center">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3">Email verification</h4>
          <p v-if="state === 'working'" class="text-muted">Verifying…</p>
          <div v-else-if="state === 'ok'" class="alert alert-success">Email verified. You can close this page.</div>
          <div v-else class="alert alert-danger">The link is invalid or expired.</div>
          <router-link to="/login" class="small">Go to sign in</router-link>
        </div>
      </div>
    </div>
  </div>
</template>
