import { defineStore } from 'pinia'
import api from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: JSON.parse(localStorage.getItem('sso_user') || 'null'),
    accessToken: localStorage.getItem('sso_access_token') || ''
  }),
  getters: {
    isAuthenticated: (s) => !!s.accessToken
  },
  actions: {
    async login(username, password) {
      const { data } = await api.post('/api/v1/auth/login', { username, password })
      this.accessToken = data.access_token
      this.user = data.user
      localStorage.setItem('sso_access_token', data.access_token)
      localStorage.setItem('sso_user', JSON.stringify(data.user))
    },
    async logout() {
      try {
        await api.post('/api/v1/auth/logout')
      } finally {
        this.accessToken = ''
        this.user = null
        localStorage.removeItem('sso_access_token')
        localStorage.removeItem('sso_user')
      }
    }
  }
})
