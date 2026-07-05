<script setup>
import { ref } from 'vue'
import api from '../api'

const login = ref('')
const sent = ref(false)
const busy = ref(false)

async function submit() {
  busy.value = true
  try {
    await api.post('/api/v1/auth/password/forgot', { login: login.value })
  } finally {
    sent.value = true // always: the endpoint never reveals whether the account exists
    busy.value = false
  }
}
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-4">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3 text-center">Reset password</h4>
          <div v-if="sent" class="alert alert-success">
            If the account exists, a reset link has been sent to its email address.
          </div>
          <form v-else @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">Username or email</label>
              <input v-model="login" class="form-control" required autofocus />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">Send reset link</button>
          </form>
          <div class="text-center mt-3">
            <router-link to="/login" class="small">Back to sign in</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
