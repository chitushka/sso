<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const clients = ref([])
const error = ref('')
const newSecret = ref(null) // {client_id, secret} shown once after create
const formOpen = ref(false)
const editingId = ref(null)

const emptyForm = () => ({
  client_id: '',
  name: '',
  type: 'confidential',
  redirect_uris: '',
  allowed_scopes: 'openid profile email',
  post_logout_redirect_uris: '',
  backchannel_logout_uri: '',
  skip_consent: false,
  enabled: true
})
const form = ref(emptyForm())

const splitList = (s) => String(s).split(/[\s,]+/).filter(Boolean)
const joinList = (a) => (a || []).join(' ')

async function load() {
  try {
    const { data } = await api.get('/api/v1/oauth/clients')
    clients.value = data
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

function openEdit(c) {
  editingId.value = c.id
  form.value = {
    client_id: c.client_id,
    name: c.name,
    type: c.type,
    redirect_uris: joinList(c.redirect_uris),
    allowed_scopes: joinList(c.allowed_scopes),
    post_logout_redirect_uris: joinList(c.post_logout_redirect_uris),
    backchannel_logout_uri: c.backchannel_logout_uri || '',
    skip_consent: c.skip_consent,
    enabled: c.enabled
  }
  formOpen.value = true
}

async function save() {
  error.value = ''
  const payload = {
    name: form.value.name,
    redirect_uris: splitList(form.value.redirect_uris),
    allowed_scopes: splitList(form.value.allowed_scopes),
    post_logout_redirect_uris: splitList(form.value.post_logout_redirect_uris),
    backchannel_logout_uri: form.value.backchannel_logout_uri,
    skip_consent: form.value.skip_consent,
    enabled: form.value.enabled
  }
  try {
    if (editingId.value) {
      await api.put(`/api/v1/oauth/clients/${editingId.value}`, payload)
    } else {
      const { data } = await api.post('/api/v1/oauth/clients', {
        ...payload,
        client_id: form.value.client_id,
        type: form.value.type
      })
      if (data.client_secret) newSecret.value = { client_id: data.client.client_id, secret: data.client_secret }
    }
    formOpen.value = false
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function remove(c) {
  if (!confirm(`Delete client "${c.client_id}"?`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/oauth/clients/${c.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">OAuth Clients</h3>
    <button class="btn btn-primary btn-sm" @click="openCreate">New client</button>
  </div>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <div v-if="newSecret" class="alert alert-warning">
    Secret for <strong>{{ newSecret.client_id }}</strong> (shown only once):
    <code class="user-select-all">{{ newSecret.secret }}</code>
    <button class="btn-close float-end" @click="newSecret = null"></button>
  </div>

  <form v-if="formOpen" class="card card-body mb-3" @submit.prevent="save">
    <div class="row g-2">
      <div class="col-md-3">
        <label class="form-label small">client_id</label>
        <input v-model="form.client_id" class="form-control" :disabled="!!editingId" required />
      </div>
      <div class="col-md-3">
        <label class="form-label small">Name</label>
        <input v-model="form.name" class="form-control" required />
      </div>
      <div class="col-md-2">
        <label class="form-label small">Type</label>
        <select v-model="form.type" class="form-select" :disabled="!!editingId">
          <option>confidential</option>
          <option>public</option>
        </select>
      </div>
      <div class="col-md-4">
        <label class="form-label small">Allowed scopes (space separated)</label>
        <input v-model="form.allowed_scopes" class="form-control" />
      </div>
      <div class="col-md-6">
        <label class="form-label small">Redirect URIs (space/comma separated)</label>
        <input v-model="form.redirect_uris" class="form-control" />
      </div>
      <div class="col-md-6">
        <label class="form-label small">Post-logout redirect URIs</label>
        <input v-model="form.post_logout_redirect_uris" class="form-control" />
      </div>
      <div class="col-md-6">
        <label class="form-label small">Back-channel logout URI</label>
        <input v-model="form.backchannel_logout_uri" class="form-control" />
      </div>
      <div class="col-md-6 d-flex align-items-end gap-4">
        <div class="form-check">
          <input v-model="form.skip_consent" class="form-check-input" type="checkbox" id="skipConsent" />
          <label class="form-check-label" for="skipConsent">Skip consent</label>
        </div>
        <div class="form-check">
          <input v-model="form.enabled" class="form-check-input" type="checkbox" id="enabled" />
          <label class="form-check-label" for="enabled">Enabled</label>
        </div>
        <button class="btn btn-success ms-auto">Save</button>
        <button type="button" class="btn btn-outline-secondary" @click="formOpen = false">Cancel</button>
      </div>
    </div>
  </form>

  <table class="table table-hover align-middle">
    <thead>
      <tr><th>client_id</th><th>Name</th><th>Type</th><th>Scopes</th><th>Consent</th><th>Enabled</th><th class="text-end">Actions</th></tr>
    </thead>
    <tbody>
      <tr v-for="c in clients" :key="c.id">
        <td><code>{{ c.client_id }}</code></td>
        <td>{{ c.name }}</td>
        <td>{{ c.type }}</td>
        <td class="small text-muted">{{ joinList(c.allowed_scopes) }}</td>
        <td><span class="badge bg-light text-dark">{{ c.skip_consent ? 'skipped' : 'required' }}</span></td>
        <td><span class="badge" :class="c.enabled ? 'bg-success' : 'bg-secondary'">{{ c.enabled ? 'yes' : 'no' }}</span></td>
        <td class="text-end">
          <button class="btn btn-outline-secondary btn-sm me-1" @click="openEdit(c)">Edit</button>
          <button class="btn btn-outline-danger btn-sm" @click="remove(c)">Delete</button>
        </td>
      </tr>
    </tbody>
  </table>
</template>
