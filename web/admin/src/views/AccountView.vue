<script setup>
import { onMounted, ref } from 'vue'
import QRCode from 'qrcode'
import api, { apiError } from '../api'
import { useI18n } from 'vue-i18n'

const me = ref(null)
const { t } = useI18n()
const error = ref('')
const notice = ref('')

const enrollment = ref(null) // {secret, otpauth_url}
const qrDataURL = ref('')
const activateCode = ref('')
const recoveryCodes = ref([])
const disableCode = ref('')
const sessions = ref([])
const pwd = ref({ old_password: '', new_password: '', confirm: '' })

async function load() {
  try {
    const { data } = await api.get('/api/v1/auth/me')
    me.value = data
  } catch (e) {
    error.value = apiError(e)
  }
  try {
    const { data } = await api.get('/api/v1/auth/sessions')
    sessions.value = data
  } catch {
    /* При ошибке раздел остаётся пустым. */
  }
}
onMounted(load)

async function changePassword() {
  error.value = ''
  notice.value = ''
  if (pwd.value.new_password !== pwd.value.confirm) {
    error.value = t('password.mismatch')
    return
  }
  try {
    await api.post('/api/v1/auth/password/change', { old_password: pwd.value.old_password, new_password: pwd.value.new_password })
    pwd.value = { old_password: '', new_password: '', confirm: '' }
    notice.value = t('account.passwordChanged')
  } catch (e) {
    error.value = apiError(e)
  }
}

async function revokeSession(id) {
  error.value = ''
  try {
    await api.delete(`/api/v1/auth/sessions/${id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function revokeAllSessions() {
  if (!confirm(t('account.confirmSignOut'))) return
  try {
    await api.delete('/api/v1/auth/sessions')
  } finally {
    window.location.href = '/login'
  }
}

async function requestVerification() {
  error.value = ''
  notice.value = ''
  try {
    await api.post('/api/v1/auth/email/request')
    notice.value = t('account.verificationSent')
  } catch (e) {
    error.value = apiError(e)
  }
}

async function enroll() {
  error.value = ''
  try {
    const { data } = await api.post('/api/v1/auth/mfa/enroll')
    enrollment.value = data
    qrDataURL.value = await QRCode.toDataURL(data.otpauth_url, { width: 200 })
  } catch (e) {
    error.value = e.response?.status === 409 ? t('account.mfaAlready') : apiError(e)
  }
}

async function activate() {
  error.value = ''
  try {
    const { data } = await api.post('/api/v1/auth/mfa/activate', { code: activateCode.value })
    recoveryCodes.value = data.recovery_codes
    enrollment.value = null
    activateCode.value = ''
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function disable() {
  error.value = ''
  notice.value = ''
  try {
    await api.post('/api/v1/auth/mfa/disable', { code: disableCode.value })
    disableCode.value = ''
    recoveryCodes.value = []
    notice.value = t('account.mfaDisabled')
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <h3 class="mb-3">{{ $t('account.title') }}</h3>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
  <div v-if="notice" class="alert alert-success py-2">{{ notice }}</div>

  <div v-if="me" class="row g-3">
    <div class="col-md-5">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <h5 class="card-title">{{ $t('account.profile') }}</h5>
          <dl class="row mb-0">
            <dt class="col-4">{{ $t('common.username') }}</dt><dd class="col-8">{{ me.username }}</dd>
            <dt class="col-4">{{ $t('common.name') }}</dt><dd class="col-8">{{ [me.first_name, me.last_name].filter(Boolean).join(' ') || '—' }}</dd>
            <dt class="col-4">{{ $t('common.email') }}</dt>
            <dd class="col-8">
              {{ me.email }}
              <span class="badge ms-1" :class="me.email_verified ? 'bg-success' : 'bg-warning text-dark'">
                {{ me.email_verified ? $t('account.verified') : $t('account.notVerified') }}
              </span>
            </dd>
            <dt class="col-4">{{ $t('common.source') }}</dt><dd class="col-8">{{ me.source }}</dd>
          </dl>
          <button v-if="!me.email_verified" class="btn btn-outline-primary btn-sm mt-2" @click="requestVerification">
            {{ $t('account.sendVerification') }}
          </button>
        </div>
      </div>
    </div>

    <div class="col-md-7">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <h5 class="card-title">
            {{ $t('account.mfa') }}
            <span class="badge ms-1" :class="me.mfa_enabled ? 'bg-success' : 'bg-secondary'">
              {{ me.mfa_enabled ? $t('account.on') : $t('account.off') }}
            </span>
          </h5>

          <div v-if="recoveryCodes.length" class="alert alert-warning">
            <strong>{{ $t('account.recoveryCodes') }}</strong> — {{ $t('account.recoveryHelp') }}
            <div class="font-monospace mt-2">
              <div v-for="c in recoveryCodes" :key="c">{{ c }}</div>
            </div>
          </div>

          <template v-if="!me.mfa_enabled">
            <button v-if="!enrollment" class="btn btn-primary btn-sm" @click="enroll">{{ $t('account.setupMFA') }}</button>
            <div v-else class="mt-2">
              <p class="small text-muted mb-2">{{ $t('account.scanQR') }}</p>
              <img v-if="qrDataURL" :src="qrDataURL" alt="TOTP QR" class="border rounded mb-2" />
              <p class="small">{{ $t('account.secret') }}: <code class="user-select-all">{{ enrollment.secret }}</code></p>
              <form class="row g-2" @submit.prevent="activate">
                <div class="col-auto"><input v-model="activateCode" class="form-control form-control-sm" placeholder="123456" required /></div>
                <div class="col-auto"><button class="btn btn-success btn-sm">{{ $t('account.activate') }}</button></div>
              </form>
            </div>
          </template>

          <template v-else>
            <form class="row g-2 mt-1" @submit.prevent="disable">
              <div class="col-auto"><input v-model="disableCode" class="form-control form-control-sm" :placeholder="$t('account.codeHint')" required /></div>
              <div class="col-auto"><button class="btn btn-outline-danger btn-sm">{{ $t('account.disableMFA') }}</button></div>
            </form>
          </template>
        </div>
      </div>
    </div>

    <div class="col-md-5" v-if="me.source === 'local'">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <h5 class="card-title">{{ $t('account.changePassword') }}</h5>
          <form @submit.prevent="changePassword">
            <div class="mb-2"><input v-model="pwd.old_password" type="password" class="form-control form-control-sm" :placeholder="$t('account.currentPassword')" autocomplete="current-password" required /></div>
            <div class="mb-2"><input v-model="pwd.new_password" type="password" class="form-control form-control-sm" :placeholder="$t('account.newPasswordHint')" autocomplete="new-password" minlength="12" maxlength="128" required /></div>
            <div class="mb-2"><input v-model="pwd.confirm" type="password" class="form-control form-control-sm" :placeholder="$t('account.repeatPassword')" autocomplete="new-password" minlength="12" maxlength="128" required /></div>
            <button class="btn btn-primary btn-sm">{{ $t('account.changePassword') }}</button>
          </form>
        </div>
      </div>
    </div>

    <div class="col-md-7">
      <div class="card shadow-sm h-100">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">{{ $t('account.sessions') }}</h5>
            <button class="btn btn-outline-danger btn-sm" @click="revokeAllSessions">{{ $t('account.signOutEverywhere') }}</button>
          </div>
          <table class="table table-sm align-middle mt-2 mb-0">
            <tbody>
              <tr v-for="s in sessions" :key="s.id">
                <td class="small text-muted">{{ new Date(s.created_at).toLocaleString() }}</td>
                <td class="small">{{ s.ip }}</td>
                <td class="small text-truncate session-user-agent">{{ s.user_agent }}</td>
                <td class="text-end"><button class="btn btn-outline-danger btn-sm" @click="revokeSession(s.id)">{{ $t('account.revoke') }}</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.session-user-agent {
  max-width: 220px;
}
</style>
