<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const groups = ref([])
const roles = ref([])
const error = ref('')
const creating = ref(false)
const createForm = ref({ code: '', name: '', description: '' })
const editing = ref(null)
const editForm = ref({})
const rolesFor = ref(null)
const groupRoles = ref([])

async function load() {
  try {
    const [g, r] = await Promise.all([api.get('/api/v1/groups'), api.get('/api/v1/roles')])
    groups.value = g.data
    roles.value = r.data
  } catch (e) {
    error.value = apiError(e)
  }
}
onMounted(load)

async function createGroup() {
  error.value = ''
  try {
    await api.post('/api/v1/groups', createForm.value)
    creating.value = false
    createForm.value = { code: '', name: '', description: '' }
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

function startEdit(g) {
  editing.value = g.id
  editForm.value = { name: g.name, description: g.description }
}

async function saveEdit(id) {
  error.value = ''
  try {
    await api.put(`/api/v1/groups/${id}`, editForm.value)
    editing.value = null
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function removeGroup(g) {
  if (!confirm(`Delete group "${g.code}"?`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/groups/${g.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function openRoles(g) {
  rolesFor.value = rolesFor.value === g.id ? null : g.id
  if (rolesFor.value) {
    const { data } = await api.get(`/api/v1/groups/${g.id}/roles`)
    groupRoles.value = (data || []).map((r) => r.id)
  }
}

async function toggleRole(groupId, role, assigned) {
  error.value = ''
  try {
    if (assigned) {
      await api.delete(`/api/v1/groups/${groupId}/roles/${role.id}`)
    } else {
      await api.post(`/api/v1/groups/${groupId}/roles`, { role_id: role.id })
    }
    const { data } = await api.get(`/api/v1/groups/${groupId}/roles`)
    groupRoles.value = (data || []).map((r) => r.id)
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">Groups</h3>
    <button class="btn btn-primary btn-sm" @click="creating = !creating">New group</button>
  </div>
  <p class="text-muted small">Members inherit every role assigned to their groups. LDAP logins can be mapped onto groups on the LDAP page.</p>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <form v-if="creating" class="card card-body mb-3" @submit.prevent="createGroup">
    <div class="row g-2">
      <div class="col-md-3"><input v-model="createForm.code" class="form-control" placeholder="code" required /></div>
      <div class="col-md-3"><input v-model="createForm.name" class="form-control" placeholder="name" required /></div>
      <div class="col-md-5"><input v-model="createForm.description" class="form-control" placeholder="description" /></div>
      <div class="col-md-1"><button class="btn btn-success w-100">Save</button></div>
    </div>
  </form>

  <table class="table table-hover align-middle">
    <thead><tr><th>Code</th><th>Name</th><th>Description</th><th class="text-end">Actions</th></tr></thead>
    <tbody>
      <template v-for="g in groups" :key="g.id">
        <tr>
          <template v-if="editing === g.id">
            <td><code>{{ g.code }}</code></td>
            <td><input v-model="editForm.name" class="form-control form-control-sm" /></td>
            <td><input v-model="editForm.description" class="form-control form-control-sm" /></td>
            <td class="text-end">
              <button class="btn btn-success btn-sm me-1" @click="saveEdit(g.id)">Save</button>
              <button class="btn btn-outline-secondary btn-sm" @click="editing = null">Cancel</button>
            </td>
          </template>
          <template v-else>
            <td><code>{{ g.code }}</code></td>
            <td>{{ g.name }}</td>
            <td class="text-muted">{{ g.description }}</td>
            <td class="text-end">
              <button class="btn btn-outline-primary btn-sm me-1" @click="openRoles(g)">Roles</button>
              <button class="btn btn-outline-secondary btn-sm me-1" @click="startEdit(g)">Edit</button>
              <button class="btn btn-outline-danger btn-sm" @click="removeGroup(g)">Delete</button>
            </td>
          </template>
        </tr>
        <tr v-if="rolesFor === g.id">
          <td colspan="4" class="bg-light">
            <div class="d-flex flex-wrap gap-3 p-2">
              <div v-for="r in roles" :key="r.id" class="form-check">
                <input
                  class="form-check-input"
                  type="checkbox"
                  :id="g.id + r.id"
                  :checked="groupRoles.includes(r.id)"
                  @change="toggleRole(g.id, r, groupRoles.includes(r.id))"
                />
                <label class="form-check-label" :for="g.id + r.id">{{ r.code }}</label>
              </div>
            </div>
          </td>
        </tr>
      </template>
    </tbody>
  </table>
  <p v-if="!groups.length" class="text-muted">No groups yet.</p>
</template>
