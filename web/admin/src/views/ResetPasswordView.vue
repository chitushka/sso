<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api, { apiError } from '../api'

const route = useRoute()
const router = useRouter()
const password = ref('')
const confirm = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  if (password.value !== confirm.value) {
    error.value = 'Passwords do not match'
    return
  }
  busy.value = true
  try {
    await api.post('/api/v1/auth/password/reset', { token: String(route.query.token || ''), password: password.value })
    router.push('/login')
  } catch (e) {
    error.value = apiError(e)
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
          <h4 class="card-title mb-3 text-center">Set a new password</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
          <form @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">New password</label>
              <input v-model="password" type="password" class="form-control" minlength="8" required autofocus />
            </div>
            <div class="mb-3">
              <label class="form-label">Repeat password</label>
              <input v-model="confirm" type="password" class="form-control" minlength="8" required />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">Save password</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
