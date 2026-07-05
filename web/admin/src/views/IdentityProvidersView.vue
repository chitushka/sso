<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const providers = ref([])
const error = ref('')
const formOpen = ref(false)
const editingId = ref(null)

const emptyForm = () => ({
  code: '',
  name: '',
  type: 'google',
  client_id: '',
  client_secret: '',
  authorize_url: '',
  token_url: '',
  userinfo_url: '',
  scopes: '',
  enabled: true
})
const form = ref(emptyForm())

async function load() {
  try {
    const { data } = await api.get('/api/v1/identity-providers')
    providers.value = data
  } catch (e) {
    error.value = apiError(e)
  }
}
onMounted(load)

function openCreate() {
  editingId.value = null
  form.value = emptyForm()
  formOpen.value = true
}

function openEdit(p) {
  editingId.value = p.id
  form.value = { ...p, client_secret: '' } // empty secret keeps the stored one
  formOpen.value = true
}

async function save() {
  error.value = ''
  try {
    if (editingId.value) {
      await api.put(`/api/v1/identity-providers/${editingId.value}`, form.value)
    } else {
      await api.post('/api/v1/identity-providers', form.value)
    }
    formOpen.value = false
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function remove(p) {
  if (!confirm(`Delete provider "${p.code}"? Users linked to it will lose this sign-in method.`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/identity-providers/${p.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">Identity Providers</h3>
    <button class="btn btn-primary btn-sm" @click="openCreate">New provider</button>
  </div>
  <p class="text-muted small">
    External sign-in ("Continue with …"). For Google/GitHub the endpoint URLs are filled automatically — register the callback
    <code>{issuer}/oauth2/broker/{code}/callback</code> at the provider.
  </p>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <form v-if="formOpen" class="card card-body mb-3" @submit.prevent="save">
    <div class="row g-2">
      <div class="col-md-2"><label class="form-label small">Code (slug)</label><input v-model="form.code" class="form-control" :disabled="!!editingId" required /></div>
      <div class="col-md-3"><label class="form-label small">Name</label><input v-model="form.name" class="form-control" required /></div>
      <div class="col-md-2">
        <label class="form-label small">Type</label>
        <select v-model="form.type" class="form-select">
          <option value="google">google</option>
          <option value="github">github</option>
          <option value="oidc">generic oidc</option>
        </select>
      </div>
      <div class="col-md-5"><label class="form-label small">Client ID</label><input v-model="form.client_id" class="form-control" required /></div>
      <div class="col-md-5">
        <label class="form-label small">Client secret <span v-if="editingId" class="text-muted">(empty = keep current)</span></label>
        <input v-model="form.client_secret" type="password" class="form-control" />
      </div>
      <div class="col-md-5"><label class="form-label small">Scopes</label><input v-model="form.scopes" class="form-control" placeholder="openid profile email" /></div>
      <div class="col-md-2 d-flex align-items-end">
        <div class="form-check"><input v-model="form.enabled" class="form-check-input" type="checkbox" id="idpEnabled" /><label class="form-check-label" for="idpEnabled">Enabled</label></div>
      </div>
      <template v-if="form.type === 'oidc'">
        <div class="col-md-4"><label class="form-label small">Authorize URL</label><input v-model="form.authorize_url" class="form-control" required /></div>
        <div class="col-md-4"><label class="form-label small">Token URL</label><input v-model="form.token_url" class="form-control" required /></div>
        <div class="col-md-4"><label class="form-label small">Userinfo URL</label><input v-model="form.userinfo_url" class="form-control" required /></div>
      </template>
      <div class="col-12 d-flex gap-2">
        <button class="btn btn-success">Save</button>
        <button type="button" class="btn btn-outline-secondary" @click="formOpen = false">Cancel</button>
      </div>
    </div>
  </form>

  <table class="table table-hover align-middle">
    <thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Client ID</th><th>Enabled</th><th class="text-end">Actions</th></tr></thead>
    <tbody>
      <tr v-for="p in providers" :key="p.id">
        <td><code>{{ p.code }}</code></td>
        <td>{{ p.name }}</td>
        <td>{{ p.type }}</td>
        <td class="small text-muted">{{ p.client_id }}</td>
        <td><span class="badge" :class="p.enabled ? 'bg-success' : 'bg-secondary'">{{ p.enabled ? 'yes' : 'no' }}</span></td>
        <td class="text-end">
          <button class="btn btn-outline-secondary btn-sm me-1" @click="openEdit(p)">Edit</button>
          <button class="btn btn-outline-danger btn-sm" @click="remove(p)">Delete</button>
        </td>
      </tr>
    </tbody>
  </table>
  <p v-if="!providers.length" class="text-muted">No identity providers configured.</p>
</template>
