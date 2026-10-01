import axios from 'axios'

// Same-origin API: in dev Vite proxies to :8080, in production the Go binary
// serves both the SPA and the API. withCredentials keeps the sso_session
// cookie flowing for the OAuth authorize/consent/logout endpoints.
const api = axios.create({ baseURL: '/', withCredentials: true })

api.interceptors.request.use((config) => {
	const method = String(config.method || 'get').toUpperCase()
	if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
		const csrf = document.cookie.split('; ').find((v) => v.startsWith('sso_csrf='))
		if (csrf) config.headers['X-CSRF-Token'] = decodeURIComponent(csrf.slice('sso_csrf='.length))
	}
	return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status
    const onLoginPage = window.location.pathname.startsWith('/login')
    if (status === 401 && !onLoginPage && !err.config?.url?.includes('/auth/login')) {
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
