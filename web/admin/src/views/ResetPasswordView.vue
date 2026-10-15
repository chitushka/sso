<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api, { apiError } from '../api'
import { useI18n } from 'vue-i18n'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const password = ref('')
const confirm = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  if (password.value !== confirm.value) {
    error.value = t('password.mismatch')
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
          <h4 class="card-title mb-3 text-center">{{ $t('password.newTitle') }}</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
          <form @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">{{ $t('password.new') }}</label>
              <input v-model="password" type="password" class="form-control" minlength="12" maxlength="128" required autofocus />
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('password.repeat') }}</label>
              <input v-model="confirm" type="password" class="form-control" minlength="12" maxlength="128" required />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ $t('password.save') }}</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
