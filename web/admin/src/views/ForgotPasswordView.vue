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
    sent.value = true // Endpoint никогда не раскрывает наличие учётной записи.
    busy.value = false
  }
}
</script>

<template>
  <div class="row justify-content-center mt-5">
    <div class="col-md-4">
      <div class="card shadow-sm">
        <div class="card-body">
          <h4 class="card-title mb-3 text-center">{{ $t('password.resetTitle') }}</h4>
          <div v-if="sent" class="alert alert-success">
            {{ $t('password.resetSent') }}
          </div>
          <form v-else @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">{{ $t('password.loginLabel') }}</label>
              <input v-model="login" class="form-control" required autofocus />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ $t('password.sendLink') }}</button>
          </form>
          <div class="text-center mt-3">
            <router-link to="/login" class="small">{{ $t('password.backToLogin') }}</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
