import axios from 'axios'
import i18n from './i18n'

// Same-origin API: при разработке Vite проксирует :8080, а в production Go-бинарник
// обслуживает SPA и API. withCredentials передаёт cookie sso_session для OAuth.
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
  const code = data?.error
  const protocolErrors = new Set([
    'invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type',
    'invalid_scope', 'server_error', 'temporarily_unavailable', 'login_required', 'consent_required'
  ])
  if (protocolErrors.has(code) && !data?.error_description) return code
  const keys = {
    400: 'errors.invalid', 401: 'errors.unauthorized', 403: 'errors.forbidden', 404: 'errors.notFound',
    409: 'errors.conflict', 429: 'errors.tooMany', 500: 'errors.server', 502: 'errors.unavailable', 503: 'errors.unavailable'
  }
  return i18n.global.t(keys[err.response?.status] || 'errors.request')
}

export default api
