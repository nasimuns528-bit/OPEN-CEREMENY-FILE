/**
 * VisionTrust Auth Context — Global Authentication State & RBAC Controls
 * Supports the 5 official roles:
 * - ADMIN
 * - DATA_CONTRIBUTOR
 * - MODEL_CONTRIBUTOR
 * - REVIEWER
 * - INFERENCE_USER
 */
import React, { createContext, useCallback, useContext, useEffect, useState } from 'react'
import api from '../api/axios'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('user')
      return stored ? JSON.parse(stored) : null
    } catch {
      return null
    }
  })
  const [loading, setLoading] = useState(true)

  // Validate session on mount
  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      setLoading(false)
      return
    }

    api.get('/auth/me')
      .then(({ data }) => {
        setUser(data)
        localStorage.setItem('user', JSON.stringify(data))
      })
      .catch(() => {
        logout()
      })
      .finally(() => setLoading(false))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(async (username, password) => {
    const { data } = await api.post('/auth/login', { username, password })
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)

    const { data: profile } = await api.get('/auth/me')
    setUser(profile)
    localStorage.setItem('user', JSON.stringify(profile))
    return profile
  }, [])

  const register = useCallback(async (username, email, password, role = 'DATA_CONTRIBUTOR') => {
    const { data } = await api.post('/auth/register', { username, email, password, role })
    return data
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      // Ignore network errors on logout
    } finally {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      localStorage.removeItem('user')
      setUser(null)
    }
  }, [])

  const currentRole = (user?.role || '').toUpperCase()

  const value = {
    user,
    loading,
    isAuthenticated: !!user,
    role: currentRole,
    isAdmin: currentRole === 'ADMIN',
    isDataContributor: currentRole === 'DATA_CONTRIBUTOR' || currentRole === 'ADMIN',
    isModelContributor: currentRole === 'MODEL_CONTRIBUTOR' || currentRole === 'ADMIN',
    isReviewer: currentRole === 'REVIEWER' || currentRole === 'ADMIN',
    isInferenceUser: currentRole === 'INFERENCE_USER' || currentRole === 'ADMIN',
    login,
    register,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
