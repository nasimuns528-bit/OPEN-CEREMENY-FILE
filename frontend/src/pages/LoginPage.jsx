/**
 * VisionTrust Login Terminal
 * - Protected against brute-force via backend sliding-window rate limiting
 * - Timing-attack resistant
 * - Displays clear error states without internal leakages
 */
import React, { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from?.pathname || '/dashboard'

  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const handleChange = (e) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }))
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.username.trim() || !form.password) {
      setError('Please provide both username and authentication key/password.')
      return
    }

    setLoading(true)
    try {
      await login(form.username.trim(), form.password)
      navigate(from, { replace: true })
    } catch (err) {
      const msg = err.response?.data?.detail || 'Authentication failed. Please verify credentials.'
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-slate-950">
      <div className="w-full max-w-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-black text-2xl mb-4 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
            VT
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-wide">
            VISION<span className="text-emerald-400">TRUST</span>
          </h1>
          <p className="text-slate-400 text-xs font-mono mt-1">COMPUTER VISION INTEGRITY ASSURANCE</p>
        </div>

        {/* Form Card */}
        <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl backdrop-blur">
          <div className="flex items-center justify-between mb-6 pb-3 border-b border-slate-800">
            <h2 className="text-sm font-mono uppercase tracking-wider text-slate-300">Identity Authentication</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
              ARGON2id
            </span>
          </div>

          {error && (
            <div className="mb-5 px-4 py-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs font-mono">
              ⚠️ {error}
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Username / Agent Handle
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                autoFocus
                value={form.username}
                onChange={handleChange}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-emerald-500 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500"
                placeholder="alice_sec"
                disabled={loading}
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label htmlFor="password" className="block text-xs font-mono uppercase text-slate-400">
                  Password Key
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-[11px] text-slate-500 hover:text-slate-300 font-mono"
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={form.password}
                onChange={handleChange}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-emerald-500 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500"
                placeholder="••••••••"
                disabled={loading}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-sm transition-colors shadow-[0_0_20px_rgba(16,185,129,0.25)] flex items-center justify-center"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <LoadingSpinner size="sm" />
                  Verifying signature…
                </span>
              ) : (
                'Authenticate'
              )}
            </button>
          </form>

          <p className="text-center text-xs text-slate-400 mt-6 font-mono">
            Unregistered contributor?{' '}
            <Link to="/register" className="text-emerald-400 hover:underline">
              Request Enrollment
            </Link>
          </p>

          {/* Quick Demo Credentials Assistant */}
          <div className="mt-6 pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Hackathon Demo Quick-Fill
              </span>
              <span className="text-[9px] font-mono text-emerald-400/80">Local Testing</span>
            </div>
            <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
              <button
                type="button"
                onClick={() => setForm({ username: 'admin', password: 'DemoAdmin2026!' })}
                className="px-2 py-1.5 rounded bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 text-left truncate transition-colors"
              >
                👑 Admin
              </button>
              <button
                type="button"
                onClick={() => setForm({ username: 'alice_data', password: 'DemoUser2026!' })}
                className="px-2 py-1.5 rounded bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 text-left truncate transition-colors"
              >
                📁 Data Contrib
              </button>
              <button
                type="button"
                onClick={() => setForm({ username: 'bob_models', password: 'DemoUser2026!' })}
                className="px-2 py-1.5 rounded bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 text-left truncate transition-colors"
              >
                🤖 Model Contrib
              </button>
              <button
                type="button"
                onClick={() => setForm({ username: 'carol_review', password: 'DemoUser2026!' })}
                className="px-2 py-1.5 rounded bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 text-left truncate transition-colors"
              >
                🛡️ Reviewer
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6 text-center text-[11px] font-mono text-slate-600">
          SECURE PROTOCOL: TLS 1.3 / AES-256-GCM / SHA-256 HASH CHAIN
        </div>
      </div>
    </div>
  )
}
