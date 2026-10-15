<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api, { apiError } from '../api'
import { useI18n } from 'vue-i18n'

const auth = useAuthStore()
const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)
const mfaToken = ref('') // Непустое значение включает шаг второго фактора.
const code = ref('')
const providers = ref([])

if (route.query.broker_error) {
  error.value = t('login.externalFailed')
}
onMounted(async () => {
  try {
    const { data } = await api.get('/api/v1/broker/providers')
    providers.value = data
  } catch {
    /* Вход по паролю остаётся доступен. */
  }
})

function brokerURL(p) {
  return `/oauth2/broker/${p.code}/login?continue=${encodeURIComponent(String(route.query.continue || '/'))}`
}

function finish(data) {
  auth.user = data.user
  auth.restored = true
  const target = String(route.query.continue || '/')
  // Для внешнего OAuth authorize нужен полный переход, чтобы cookie сессии
  // попал на backend.
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
    error.value = e.response?.status === 429 ? t('login.tooMany') : apiError(e)
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
      error.value = t('login.tooMany')
    } else if (e.response?.status === 401 && apiError(e).includes('mfa token')) {
      error.value = t('login.expired')
      mfaToken.value = ''
      code.value = ''
    } else {
      error.value = t('login.invalidCode')
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
          <h4 class="card-title mb-3 text-center">{{ $t('login.title') }}</h4>
          <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

          <form v-if="!mfaToken" @submit.prevent="submit">
            <div class="mb-3">
              <label class="form-label">{{ $t('common.username') }}</label>
              <input v-model="username" class="form-control" autocomplete="username" required autofocus />
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('common.password') }}</label>
              <input v-model="password" type="password" class="form-control" autocomplete="current-password" required />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ busy ? $t('login.signingIn') : $t('login.signIn') }}</button>
            <div class="text-center mt-3">
              <router-link to="/forgot-password" class="small">{{ $t('login.forgot') }}</router-link>
            </div>
            <template v-if="providers.length">
              <hr />
              <a v-for="p in providers" :key="p.code" class="btn btn-outline-secondary w-100 mb-2" :href="brokerURL(p)">
                {{ $t('login.continueWith', { provider: p.name }) }}
              </a>
            </template>
          </form>

          <form v-else @submit.prevent="submitCode">
            <p class="text-muted small">{{ $t('login.mfaHelp') }}</p>
            <div class="mb-3">
              <input v-model="code" class="form-control text-center" placeholder="123456" autocomplete="one-time-code" required autofocus />
            </div>
            <button class="btn btn-primary w-100" :disabled="busy">{{ $t('login.verify') }}</button>
            <button type="button" class="btn btn-link w-100 mt-1" @click="mfaToken = ''; code = ''">{{ $t('login.back') }}</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
