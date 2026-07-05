<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const providers = ref([])
const error = ref('')
const notice = ref('')
const formOpen = ref(false)
const editingId = ref(null)

const emptyForm = () => ({
  name: '',
  host: '',
  port: 389,
  use_tls: false,
  start_tls: false,
  bind_dn: '',
  bind_password: '',
  base_dn: '',
  user_filter: '',
  username_attribute: '',
  email_attribute: '',
  display_name_attribute: '',
  enabled: true
})
const form = ref(emptyForm())

async function load() {
  try {
    const { data } = await api.get('/api/v1/ldap/providers')
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
  form.value = { ...p, bind_password: '' } // empty password keeps the stored one
  formOpen.value = true
}

async function save() {
  error.value = ''
  notice.value = ''
  try {
    if (editingId.value) {
      await api.put(`/api/v1/ldap/providers/${editingId.value}`, form.value)
    } else {
      await api.post('/api/v1/ldap/providers', form.value)
    }
    formOpen.value = false
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function test() {
  error.value = ''
  notice.value = ''
  try {
    await api.post('/api/v1/ldap/providers/test', form.value)
    notice.value = 'Connection OK'
  } catch (e) {
    error.value = 'Connection failed: ' + apiError(e)
  }
}

async function remove(p) {
  if (!confirm(`Delete LDAP provider "${p.name}"?`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/ldap/providers/${p.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">LDAP Providers</h3>
    <button class="btn btn-primary btn-sm" @click="openCreate">New provider</button>
  </div>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>
  <div v-if="notice" class="alert alert-success py-2">{{ notice }}</div>

  <form v-if="formOpen" class="card card-body mb-3" @submit.prevent="save">
    <div class="row g-2">
      <div class="col-md-3"><label class="form-label small">Name</label><input v-model="form.name" class="form-control" required /></div>
      <div class="col-md-3"><label class="form-label small">Host</label><input v-model="form.host" class="form-control" required /></div>
      <div class="col-md-1"><label class="form-label small">Port</label><input v-model.number="form.port" type="number" class="form-control" /></div>
      <div class="col-md-5 d-flex align-items-end gap-4">
        <div class="form-check"><input v-model="form.use_tls" class="form-check-input" type="checkbox" id="tls" /><label class="form-check-label" for="tls">LDAPS</label></div>
        <div class="form-check"><input v-model="form.start_tls" class="form-check-input" type="checkbox" id="stls" /><label class="form-check-label" for="stls">StartTLS</label></div>
        <div class="form-check"><input v-model="form.enabled" class="form-check-input" type="checkbox" id="en" /><label class="form-check-label" for="en">Enabled</label></div>
      </div>
      <div class="col-md-4"><label class="form-label small">Bind DN</label><input v-model="form.bind_dn" class="form-control" /></div>
      <div class="col-md-4">
        <label class="form-label small">Bind password <span v-if="editingId" class="text-muted">(empty = keep current)</span></label>
        <input v-model="form.bind_password" type="password" class="form-control" />
      </div>
      <div class="col-md-4"><label class="form-label small">Base DN</label><input v-model="form.base_dn" class="form-control" /></div>
      <div class="col-md-6"><label class="form-label small">User filter</label><input v-model="form.user_filter" class="form-control" placeholder="(&(objectClass=user)(sAMAccountName={username}))" /></div>
      <div class="col-md-2"><label class="form-label small">Username attr</label><input v-model="form.username_attribute" class="form-control" placeholder="sAMAccountName" /></div>
      <div class="col-md-2"><label class="form-label small">Email attr</label><input v-model="form.email_attribute" class="form-control" placeholder="mail" /></div>
      <div class="col-md-2"><label class="form-label small">Display name attr</label><input v-model="form.display_name_attribute" class="form-control" placeholder="displayName" /></div>
      <div class="col-12 d-flex gap-2">
        <button class="btn btn-success">Save</button>
        <button type="button" class="btn btn-outline-primary" @click="test">Test connection</button>
        <button type="button" class="btn btn-outline-secondary" @click="formOpen = false">Cancel</button>
      </div>
    </div>
  </form>

  <table class="table table-hover align-middle">
    <thead><tr><th>Name</th><th>Host</th><th>Security</th><th>Base DN</th><th>Enabled</th><th class="text-end">Actions</th></tr></thead>
    <tbody>
      <tr v-for="p in providers" :key="p.id">
        <td>{{ p.name }}</td>
        <td><code>{{ p.host }}:{{ p.port }}</code></td>
        <td>{{ p.use_tls ? 'LDAPS' : p.start_tls ? 'StartTLS' : 'plain' }}</td>
        <td class="small text-muted">{{ p.base_dn }}</td>
        <td><span class="badge" :class="p.enabled ? 'bg-success' : 'bg-secondary'">{{ p.enabled ? 'yes' : 'no' }}</span></td>
        <td class="text-end">
          <button class="btn btn-outline-secondary btn-sm me-1" @click="openEdit(p)">Edit</button>
          <button class="btn btn-outline-danger btn-sm" @click="remove(p)">Delete</button>
        </td>
      </tr>
    </tbody>
  </table>
</template>
