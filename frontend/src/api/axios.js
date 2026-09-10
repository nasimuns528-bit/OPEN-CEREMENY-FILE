/**
 * Axios instance for VisionTrust API.
 * - Auto-attaches Authorization Bearer header from localStorage
 * - Auto-refreshes access token on 401 (one retry)
 * - Clears auth on unrecoverable 401
 */
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// ── Request interceptor: attach access token ──────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error),
)

// ── Response interceptor: refresh on 401 ─────────────────────────────────
let _isRefreshing = false
let _pendingQueue = []

const processQueue = (error, token = null) => {
  _pendingQueue.forEach(({ resolve, reject }) => {
    error ? reject(error) : resolve(token)
  })
  _pendingQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config

    if (error.response?.status === 401 && !original._retry) {
      // Don't retry auth endpoints themselves
      if (original.url?.includes('/auth/login') || original.url?.includes('/auth/refresh')) {
        return Promise.reject(error)
      }

      if (_isRefreshing) {
        return new Promise((resolve, reject) => {
          _pendingQueue.push({ resolve, reject })
        }).then((token) => {
          original.headers.Authorization = `Bearer ${token}`
          return api(original)
        })
      }

      original._retry = true
      _isRefreshing = true

      const refreshToken = localStorage.getItem('refresh_token')
      if (!refreshToken) {
        _isRefreshing = false
        _clearAuth()
        return Promise.reject(error)
      }

      try {
        const { data } = await axios.post(`${BASE_URL}/api/v1/auth/refresh`, {
          refresh_token: refreshToken,
        })
        localStorage.setItem('access_token', data.access_token)
        localStorage.setItem('refresh_token', data.refresh_token)
        api.defaults.headers.common.Authorization = `Bearer ${data.access_token}`
        processQueue(null, data.access_token)
        original.headers.Authorization = `Bearer ${data.access_token}`
        return api(original)
      } catch (refreshError) {
        processQueue(refreshError, null)
        _clearAuth()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        _isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

function _clearAuth() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
  localStorage.removeItem('user')
}

export default api
