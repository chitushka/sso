<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { apiError } from '../api'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    await auth.login(username.value, password.value)
    const target = route.query.continue || '/'
    // The continue target can be an external OAuth authorize URL — use a full
    // navigation so the sso_session cookie is presented to the backend.
    if (String(target).startsWith('/oauth2/')) {
      window.location.href = String(target)
    } else {
      router.push(String(target))
    }
  } catch (e) {
    error.value = e.response?.status === 429 ? 'Too many failed attempts, try again later' : apiError(e)
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
          <form @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">Username</label>
              <input v-model="username" class="form-control" autocomplete="username" required autofocus />
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input v-model="password" type="password" class="form-control" autocomplete="current-password" required />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
