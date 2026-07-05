<script setup>
import { onMounted, ref } from 'vue'
import api, { apiError } from '../api'

const rolesList = ref([])
const permissions = ref([])
const error = ref('')
const creating = ref(false)
const createForm = ref({ code: '', name: '', description: '' })
const editing = ref(null)
const editForm = ref({})
const permsFor = ref(null)
const rolePerms = ref([])

async function load() {
  try {
    const [r, p] = await Promise.all([api.get('/api/v1/roles'), api.get('/api/v1/permissions')])
    rolesList.value = r.data
    permissions.value = p.data
  } catch (e) {
    error.value = apiError(e)
  }
}
onMounted(load)

async function createRole() {
  error.value = ''
  try {
    await api.post('/api/v1/roles', createForm.value)
    creating.value = false
    createForm.value = { code: '', name: '', description: '' }
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

function startEdit(r) {
  editing.value = r.id
  editForm.value = { name: r.name, description: r.description }
}

async function saveEdit(id) {
  error.value = ''
  try {
    await api.put(`/api/v1/roles/${id}`, editForm.value)
    editing.value = null
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function removeRole(r) {
  if (!confirm(`Delete role "${r.code}"?`)) return
  error.value = ''
  try {
    await api.delete(`/api/v1/roles/${r.id}`)
    await load()
  } catch (e) {
    error.value = apiError(e)
  }
}

async function openPerms(r) {
  permsFor.value = permsFor.value === r.id ? null : r.id
  if (permsFor.value) {
    const { data } = await api.get(`/api/v1/roles/${r.id}/permissions`)
    rolePerms.value = (data || []).map((p) => p.id)
  }
}

async function togglePerm(roleId, perm, assigned) {
  error.value = ''
  try {
    if (assigned) {
      await api.delete(`/api/v1/roles/${roleId}/permissions/${perm.id}`)
    } else {
      await api.post(`/api/v1/roles/${roleId}/permissions`, { permission_id: perm.id })
    }
    const { data } = await api.get(`/api/v1/roles/${roleId}/permissions`)
    rolePerms.value = (data || []).map((p) => p.id)
  } catch (e) {
    error.value = apiError(e)
  }
}
</script>

<template>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3 class="mb-0">Roles</h3>
    <button class="btn btn-primary btn-sm" @click="creating = !creating">New role</button>
  </div>
  <div v-if="error" class="alert alert-danger py-2">{{ error }}</div>

  <form v-if="creating" class="card card-body mb-3" @submit.prevent="createRole">
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
      <template v-for="r in rolesList" :key="r.id">
        <tr>
          <template v-if="editing === r.id">
            <td><code>{{ r.code }}</code></td>
            <td><input v-model="editForm.name" class="form-control form-control-sm" /></td>
            <td><input v-model="editForm.description" class="form-control form-control-sm" /></td>
            <td class="text-end">
              <button class="btn btn-success btn-sm me-1" @click="saveEdit(r.id)">Save</button>
              <button class="btn btn-outline-secondary btn-sm" @click="editing = null">Cancel</button>
            </td>
          </template>
          <template v-else>
            <td><code>{{ r.code }}</code></td>
            <td>{{ r.name }}</td>
            <td class="text-muted">{{ r.description }}</td>
            <td class="text-end">
              <button class="btn btn-outline-primary btn-sm me-1" @click="openPerms(r)">Permissions</button>
              <button class="btn btn-outline-secondary btn-sm me-1" @click="startEdit(r)">Edit</button>
              <button
                class="btn btn-outline-danger btn-sm"
                :disabled="r.code === 'admin' || r.code === 'user'"
                @click="removeRole(r)"
              >
                Delete
              </button>
            </td>
          </template>
        </tr>
        <tr v-if="permsFor === r.id">
          <td colspan="4" class="bg-light">
            <div class="d-flex flex-wrap gap-3 p-2">
              <div v-for="p in permissions" :key="p.id" class="form-check">
                <input
                  class="form-check-input"
                  type="checkbox"
                  :id="r.id + p.id"
                  :checked="rolePerms.includes(p.id)"
                  @change="togglePerm(r.id, p, rolePerms.includes(p.id))"
                />
                <label class="form-check-label" :for="r.id + p.id"><code>{{ p.code }}</code></label>
              </div>
            </div>
          </td>
        </tr>
      </template>
    </tbody>
  </table>
</template>
