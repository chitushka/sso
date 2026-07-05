<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api, { apiError } from '../api'

// Opened by the client app after /oauth2/authorize returned consent_required:
// /consent?client_id=...&scope=...&continue=<original authorize URL>
const route = useRoute()
const info = ref(null)
const error = ref('')
const busy = ref(false)

const clientId = String(route.query.client_id || '')
const scope = String(route.query.scope || '')
const continueUrl = String(route.query.continue || '')

onMounted(async () => {
  try {
    const { data } = await api.get('/oauth2/consent', { params: { client_id: clientId, scope } })
    info.value = data
  } catch (e) {
    if (e.response?.status === 401) {
      window.location.href = '/login?continue=' + encodeURIComponent(route.fullPath)
      return
    }
    error.value = apiError(e)
  }
})

async function approve() {
  busy.value = true
  error.value = ''
  try {
    await api.post('/oauth2/consent', { client_id: clientId, scope })
    if (continueUrl.startsWith('/oauth2/')) {
      window.location.href = continueUrl
    } else {
      window.location.href = '/'
    }
  } catch (e) {
    error.value = apiError(e)
    busy.value = false
  }
}

function deny() {
  window.location.href = '/'
}
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-5">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3">Authorize application</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
          <template v-if="info">
            <p>
              <strong>{{ info.client_name || info.client_id }}</strong> requests access to:
            </p>
            <ul>
              <li v-for="s in info.requested_scopes" :key="s">
                <code>{{ s }}</code>
                <span v-if="info.granted_scopes.includes(s)" class="badge bg-secondary ms-2">already granted</span>
              </li>
            </ul>
            <div class="d-flex gap-2">
              <button class="btn btn-primary" :disabled="busy" @click="approve">Allow</button>
              <button class="btn btn-outline-secondary" :disabled="busy" @click="deny">Deny</button>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
