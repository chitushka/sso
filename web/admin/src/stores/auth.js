import { defineStore } from 'pinia'
import api from '../api'

export const useAuthStore = defineStore('auth', {
	state: () => ({
		user: null,
		restored: false
	}),
	getters: {
		isAuthenticated: (s) => !!s.user
	},
	actions: {
		async restore() {
			if (this.restored) return
			try {
				const { data } = await api.get('/api/v1/auth/me')
				this.user = data
			} catch {
				this.user = null
			} finally {
				this.restored = true
			}
		},
    async logout() {
      try {
        await api.post('/api/v1/auth/logout')
      } finally {
			this.user = null
      }
    }
  }
})
