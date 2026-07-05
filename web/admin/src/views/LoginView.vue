<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api, { apiError } from '../api'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)
const mfaToken = ref('') // non-empty → second factor step
const code = ref('')

function finish(data) {
  auth.accessToken = data.access_token
  auth.user = data.user
  localStorage.setItem('sso_access_token', data.access_token)
  localStorage.setItem('sso_user', JSON.stringify(data.user))
  const target = String(route.query.continue || '/')
  // External OAuth authorize URLs need a full navigation so the session
  // cookie reaches the backend.
  if (target.startsWith('/oauth2/')) {
    window.location.href = target
  } else {
    router.push(target)
  }
}

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const { data } = await api.post('/api/v1/auth/login', { username: username.value, password: password.value })
    if (data.mfa_required) {
      mfaToken.value = data.mfa_token
    } else {
      finish(data)
    }
  } catch (e) {
    error.value = e.response?.status === 429 ? 'Too many failed attempts, try again later' : apiError(e)
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  error.value = ''
  busy.value = true
  try {
    const { data } = await api.post('/api/v1/auth/mfa/verify', { mfa_token: mfaToken.value, code: code.value })
    finish(data)
  } catch (e) {
    if (e.response?.status === 429) {
      error.value = 'Too many failed attempts, try again later'
    } else if (e.response?.status === 401 && apiError(e).includes('mfa token')) {
      error.value = 'Session expired, sign in again'
      mfaToken.value = ''
      code.value = ''
    } else {
      error.value = 'Invalid code'
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-4">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3 text-center">SSO Sign in</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

          <form v-if="!mfaToken" @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">Username</label>
              <input v-model="username" class="form-control" autocomplete="username" required autofocus />
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input v-model="password" type="password" class="form-control" autocomplete="current-password" required />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
            <div class="text-center mt-3">
              <router-link to="/forgot-password" class="small">Forgot password?</router-link>
            </div>
          </form>

          <form v-else @submit.prevent="submitCode">
            <p class="text-muted small">Enter the 6-digit code from your authenticator app, or a recovery code.</p>
            <div class="mb-3">
              <input v-model="code" class="form-control text-center" placeholder="123456" autocomplete="one-time-code" required autofocus />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">Verify</button>
            <button type="button" class="btn btn-link w-100 mt-1" @click="mfaToken = ''; code = ''">Back</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
