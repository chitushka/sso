import axios from 'axios'

// Same-origin API: in dev Vite proxies to :8080, in production the Go binary
// serves both the SPA and the API. withCredentials keeps the sso_session
// cookie flowing for the OAuth authorize/consent/logout endpoints.
const api = axios.create({ baseURL: '/', withCredentials: true })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sso_access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status
    const onLoginPage = window.location.pathname.startsWith('/login')
    if (status === 401 && !onLoginPage && !err.config?.url?.includes('/auth/login')) {
      localStorage.removeItem('sso_access_token')
      localStorage.removeItem('sso_user')
      window.location.href = '/login?continue=' + encodeURIComponent(window.location.pathname + window.location.search)
    }
    return Promise.reject(err)
  }
)

export function apiError(err) {
  const data = err.response?.data
  return data?.error_description || data?.error || err.message || 'request failed'
}

export default api
