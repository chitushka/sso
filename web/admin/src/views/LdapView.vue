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
  group_attribute: 'memberOf',
  enabled: true
})
const form = ref(emptyForm())

// Group mappings panel
const groups = ref([])
const mappingsFor = ref(null)
const mappings = ref([])
const newMapping = ref({ ldap_group: '', group_id: '' })

async function openMappings(p) {
  mappingsFor.value = mappingsFor.value === p.id ? null : p.id
  if (!mappingsFor.value) return
  try {
    const [m, g] = await Promise.all([
      api.get(`/api/v1/ldap/providers/${p.id}/group-mappings`),
      api.get('/api/v1/groups')
    ])
    mappings.value = m.data
    groups.value = g.data
  } catch (e) {
    error.value = apiError(e)
  }
}

async function addMapping(providerId) {
  error.value = ''
  try {
    await api.post(`/api/v1/ldap/providers/${providerId}/group-mappings`, newMapping.value)
    newMapping.value = { ldap_group: '', group_id: '' }
    const { data } = await api.get(`/api/v1/ldap/providers/${providerId}/group-mappings`)
    mappings.value = data
  } catch (e) {
    error.value = apiError(e)
  }
}

async function removeMapping(providerId, id) {
  error.value = ''
  try {
    await api.delete(`/api/v1/ldap/providers/${providerId}/group-mappings/${id}`)
    const { data } = await api.get(`/api/v1/ldap/providers/${providerId}/group-mappings`)
    mappings.value = data
  } catch (e) {
    error.value = apiError(e)
  }
}

function groupCode(id) {
  return groups.value.find((g) => g.id === id)?.code || id
}

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
      <div class="col-md-2"><label class="form-label small">Group attr</label><input v-model="form.group_attribute" class="form-control" placeholder="memberOf" /></div>
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
      <template v-for="p in providers" :key="p.id">
        <tr>
          <td>{{ p.name }}</td>
          <td><code>{{ p.host }}:{{ p.port }}</code></td>
          <td>{{ p.use_tls ? 'LDAPS' : p.start_tls ? 'StartTLS' : 'plain' }}</td>
          <td class="small text-muted">{{ p.base_dn }}</td>
          <td><span class="badge" :class="p.enabled ? 'bg-success' : 'bg-secondary'">{{ p.enabled ? 'yes' : 'no' }}</span></td>
          <td class="text-end">
            <button class="btn btn-outline-primary btn-sm me-1" @click="openMappings(p)">Group mappings</button>
            <button class="btn btn-outline-secondary btn-sm me-1" @click="openEdit(p)">Edit</button>
            <button class="btn btn-outline-danger btn-sm" @click="remove(p)">Delete</button>
          </td>
        </tr>
        <tr v-if="mappingsFor === p.id">
          <td colspan="6" class="bg-light">
            <div class="p-2">
              <p class="small text-muted mb-2">Directory groups (as returned by <code>{{ p.group_attribute || 'memberOf' }}</code>) are mapped to SSO groups at login.</p>
              <table class="table table-sm mb-2">
                <tbody>
                  <tr v-for="m in mappings" :key="m.id">
                    <td class="small font-monospace">{{ m.ldap_group }}</td>
                    <td class="small">→ <code>{{ groupCode(m.group_id) }}</code></td>
                    <td class="text-end"><button class="btn btn-outline-danger btn-sm" @click="removeMapping(p.id, m.id)">Remove</button></td>
                  </tr>
                </tbody>
              </table>
              <form class="row g-2" @submit.prevent="addMapping(p.id)">
                <div class="col-md-6"><input v-model="newMapping.ldap_group" class="form-control form-control-sm" placeholder="CN=Admins,OU=Groups,DC=example,DC=org" required /></div>
                <div class="col-md-4">
                  <select v-model="newMapping.group_id" class="form-select form-select-sm" required>
                    <option value="" disabled>SSO group…</option>
                    <option v-for="g in groups" :key="g.id" :value="g.id">{{ g.code }}</option>
                  </select>
                </div>
                <div class="col-md-2"><button class="btn btn-success btn-sm w-100">Add mapping</button></div>
              </form>
            </div>
          </td>
        </tr>
      </template>
    </tbody>
  </table>
</template>
