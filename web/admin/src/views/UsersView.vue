<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const users = ref([])
const roles = ref([])
const error = ref('')
const creating = ref(false)
const createForm = ref({ username: '', email: '', password: '', status: 'active' })
const editing = ref(null) // user id being edited
const editForm = ref({})
const rolesFor = ref(null) // user id whose roles panel is open
const userRoles = ref([])

async function load() {
  try {
    const [u, r] = await Promise.all([api.get('/api/v1/users?limit=100'), api.get('/api/v1/roles')])
    users.value = u.data
    roles.value = r.data
  } catch (e) {
    error.value = apiError(e)
  }
}
onMounted(load)

async function createUser() {
  error.value = ''
  try {
    await api.post('/api/v1/users', createForm.value)
    creating.value = false
    createForm.value = { username: '', email: '', password: '', status: 'active' }
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

function startEdit(u) {
  editing.value = u.id
  editForm.value = { username: u.username, email: u.email, status: u.status }
}

async function saveEdit(id) {
  error.value = ''
  try {
    await api.put(`/api/v1/users/${id}`, editForm.value)
    editing.value = null
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function removeUser(u) {
  if (!confirm(`Delete user "${u.username}"? The account will be deactivated.`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/users/${u.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function openRoles(u) {
  rolesFor.value = rolesFor.value === u.id ? null : u.id
  if (rolesFor.value) {
    const { data } = await api.get(`/api/v1/users/${u.id}/roles`)
    userRoles.value = (data || []).map((r) => r.id)
  }
}

async function toggleRole(userId, role, assigned) {
  error.value = ''
  try {
    if (assigned) {
      await api.delete(`/api/v1/users/${userId}/roles/${role.id}`)
    } else {
      await api.post(`/api/v1/users/${userId}/roles`, { role_id: role.id })
    }
    const { data } = await api.get(`/api/v1/users/${userId}/roles`)
    userRoles.value = (data || []).map((r) => r.id)
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">Users</h3>
    <button class="btn btn-primary btn-sm" @click="creating = !creating">New user</button>
  </div>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <form v-if="creating" class="card card-body mb-3" @submit.prevent="createUser">
    <div class="row g-2">
      <div class="col-md-3"><input v-model="createForm.username" class="form-control" placeholder="username" required /></div>
      <div class="col-md-3"><input v-model="createForm.email" type="email" class="form-control" placeholder="email" required /></div>
      <div class="col-md-3"><input v-model="createForm.password" type="password" class="form-control" placeholder="password (min 8)" required /></div>
      <div class="col-md-2">
        <select v-model="createForm.status" class="form-select">
          <option>active</option>
          <option>blocked</option>
          <option>pending</option>
        </select>
      </div>
      <div class="col-md-1"><button class="btn btn-success w-100">Save</button></div>
    </div>
  </form>

  <table class="table table-hover align-middle">
    <thead>
      <tr><th>Username</th><th>Email</th><th>Status</th><th>Source</th><th>Last login</th><th class="text-end">Actions</th></tr>
    </thead>
    <tbody>
      <template v-for="u in users" :key="u.id">
        <tr>
          <template v-if="editing === u.id">
            <td><input v-model="editForm.username" class="form-control form-control-sm" /></td>
            <td><input v-model="editForm.email" class="form-control form-control-sm" /></td>
            <td>
              <select v-model="editForm.status" class="form-select form-select-sm">
                <option>active</option><option>blocked</option><option>pending</option><option>deleted</option>
              </select>
            </td>
            <td>{{ u.source }}</td>
            <td></td>
            <td class="text-end">
              <button class="btn btn-success btn-sm me-1" @click="saveEdit(u.id)">Save</button>
              <button class="btn btn-outline-secondary btn-sm" @click="editing = null">Cancel</button>
            </td>
          </template>
          <template v-else>
            <td>{{ u.username }}</td>
            <td>{{ u.email }}</td>
            <td><span class="badge" :class="u.status === 'active' ? 'bg-success' : 'bg-secondary'">{{ u.status }}</span></td>
            <td>{{ u.source }}</td>
            <td class="text-muted small">{{ u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—' }}</td>
            <td class="text-end">
              <button class="btn btn-outline-primary btn-sm me-1" @click="openRoles(u)">Roles</button>
              <button class="btn btn-outline-secondary btn-sm me-1" @click="startEdit(u)">Edit</button>
              <button class="btn btn-outline-danger btn-sm" @click="removeUser(u)">Delete</button>
            </td>
          </template>
        </tr>
        <tr v-if="rolesFor === u.id">
          <td colspan="6" class="bg-light">
            <div class="d-flex flex-wrap gap-3 p-2">
              <div v-for="r in roles" :key="r.id" class="form-check">
                <input
                  class="form-check-input"
                  type="checkbox"
                  :id="u.id + r.id"
                  :checked="userRoles.includes(r.id)"
                  @change="toggleRole(u.id, r, userRoles.includes(r.id))"
                />
                <label class="form-check-label" :for="u.id + r.id">{{ r.code }}</label>
              </div>
            </div>
          </td>
        </tr>
      </template>
    </tbody>
  </table>
</template>
