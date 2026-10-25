<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import api, { apiError } from '../api'

const route = useRoute()
const info = ref(null)
const error = ref('')
const busy = ref(false)

const requestToken = String(route.query.request || '')

onMounted(async () => {
  try {
    const { data } = await api.get('/oauth2/consent', { params: { request: requestToken } })
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
    const { data } = await api.post('/oauth2/consent', { request: requestToken, decision: 'allow' })
    window.location.href = data.redirect
  } catch (e) {
    error.value = apiError(e)
    busy.value = false
  }
}

async function deny() {
  busy.value = true
  error.value = ''
  try {
    const { data } = await api.post('/oauth2/consent', { request: requestToken, decision: 'deny' })
    window.location.href = data.redirect
  } catch (e) {
    error.value = apiError(e)
    busy.value = false
  }
}
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-5">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3">{{ $t('consent.title') }}</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
          <template v-if="info">
            <p>
              {{ $t('consent.requests', { client: info.client_name || info.client_id }) }}
            </p>
            <ul>
              <li v-for="s in info.requested_scopes" :key="s">
                <code>{{ s }}</code>
                <span v-if="info.granted_scopes.includes(s)" class="badge bg-secondary ms-2">{{ $t('consent.granted') }}</span>
              </li>
            </ul>
            <div class="d-flex gap-2">
              <button class="btn btn-primary" :disabled="busy" @click="approve">{{ $t('consent.allow') }}</button>
              <button class="btn btn-outline-secondary" :disabled="busy" @click="deny">{{ $t('consent.deny') }}</button>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
