/**
 * VisionTrust Register Page
 * - Supports public registration for:
 *   - DATA_CONTRIBUTOR (Uploads datasets, verifies provenance)
 *   - MODEL_CONTRIBUTOR (Registers trained models)
 *   - REVIEWER (Performs model audit & security reviews)
 *   - INFERENCE_USER (Runs inference & checks signatures)
 * - ADMIN role can only be assigned by an existing admin or system bootstrap
 */
import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

function PasswordStrength({ password }) {
  const checks = [
    { label: '8+ characters', ok: password.length >= 8 },
    { label: 'Uppercase letter (A-Z)', ok: /[A-Z]/.test(password) },
    { label: 'Numeric digit (0-9)', ok: /[0-9]/.test(password) },
  ]
  if (!password) return null
  return (
    <ul className="mt-2 space-y-1">
      {checks.map((c) => (
        <li key={c.label} className={`flex items-center gap-1.5 text-xs font-mono ${c.ok ? 'text-emerald-400' : 'text-slate-500'}`}>
          <span>{c.ok ? '✓' : '○'}</span>
          {c.label}
        </li>
      ))}
    </ul>
  )
}

export default function RegisterPage() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'DATA_CONTRIBUTOR',
  })
  const [errors, setErrors] = useState({})
  const [apiError, setApiError] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  const handleChange = (e) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }))
    setErrors((prev) => ({ ...prev, [e.target.name]: '' }))
    setApiError('')
  }

  const validate = () => {
    const errs = {}
    if (!/^[a-zA-Z0-9_\-]{3,64}$/.test(form.username))
      errs.username = 'Username must be 3–64 characters (letters, numbers, _ or - only).'
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      errs.email = 'Enter a valid email address.'
    if (form.password.length < 8 || !/[A-Z]/.test(form.password) || !/[0-9]/.test(form.password))
      errs.password = 'Password must be 8+ chars with at least one uppercase letter and one digit.'
    if (form.password !== form.confirmPassword)
      errs.confirmPassword = 'Passwords do not match.'
    return errs
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) {
      setErrors(errs)
      return
    }

    setLoading(true)
    try {
      await register(form.username, form.email, form.password, form.role)
      setSuccess(true)
      setTimeout(() => navigate('/login'), 1800)
    } catch (err) {
      const msg = err.response?.data?.detail || 'Registration failed. Please try again.'
      setApiError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4 bg-slate-950">
        <div className="max-w-md w-full p-8 rounded-2xl bg-slate-900 border border-emerald-500/30 text-center shadow-[0_0_30px_rgba(16,185,129,0.15)]">
          <div className="text-5xl mb-4">🛡️</div>
          <h2 className="text-xl font-bold text-slate-100 mb-2">Account Provisioned</h2>
          <p className="text-emerald-400 font-mono text-sm">Identity registered into trust chain.</p>
          <p className="text-slate-400 text-xs mt-2">Redirecting to sign-in terminal...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-slate-950">
      <div className="w-full max-w-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-black text-2xl mb-4 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
            VT
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-wide">
            VISION<span className="text-emerald-400">TRUST</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1 font-mono text-xs">JOIN THE CRYPTOGRAPHIC TRUST CHAIN</p>
        </div>

        <div className="p-8 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl backdrop-blur">
          {apiError && (
            <div className="mb-4 px-4 py-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs font-mono">
              ⚠️ {apiError}
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                autoFocus
                value={form.username}
                onChange={handleChange}
                className={`w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border ${
                  errors.username ? 'border-red-600' : 'border-slate-800 focus:border-emerald-500'
                } text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500`}
                placeholder="alice_sec"
                disabled={loading}
              />
              {errors.username && <p className="mt-1 text-xs text-red-400 font-mono">{errors.username}</p>}
            </div>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Security Contact Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                value={form.email}
                onChange={handleChange}
                className={`w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border ${
                  errors.email ? 'border-red-600' : 'border-slate-800 focus:border-emerald-500'
                } text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500`}
                placeholder="alice@defense.org"
                disabled={loading}
              />
              {errors.email && <p className="mt-1 text-xs text-red-400 font-mono">{errors.email}</p>}
            </div>

            {/* Role Selection */}
            <div>
              <label htmlFor="role" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Assigned Operational Role
              </label>
              <select
                id="role"
                name="role"
                value={form.role}
                onChange={handleChange}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-emerald-500 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500"
                disabled={loading}
              >
                <option value="DATA_CONTRIBUTOR">Data Contributor — Upload datasets & file hashes</option>
                <option value="MODEL_CONTRIBUTOR">Model Contributor — Upload model weights & architecture</option>
                <option value="REVIEWER">Reviewer — Model approval & security audits</option>
                <option value="INFERENCE_USER">Inference User — Run verified model inference</option>
              </select>
              <p className="mt-1 text-[11px] text-slate-500">ADMIN governance privileges require executive bootstrap.</p>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={handleChange}
                className={`w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border ${
                  errors.password ? 'border-red-600' : 'border-slate-800 focus:border-emerald-500'
                } text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500`}
                placeholder="••••••••"
                disabled={loading}
              />
              {errors.password && <p className="mt-1 text-xs text-red-400 font-mono">{errors.password}</p>}
              <PasswordStrength password={form.password} />
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="confirmPassword" className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                value={form.confirmPassword}
                onChange={handleChange}
                className={`w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border ${
                  errors.confirmPassword ? 'border-red-600' : 'border-slate-800 focus:border-emerald-500'
                } text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500`}
                placeholder="••••••••"
                disabled={loading}
              />
              {errors.confirmPassword && (
                <p className="mt-1 text-xs text-red-400 font-mono">{errors.confirmPassword}</p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-3 py-2.5 px-4 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-sm transition-colors shadow-[0_0_20px_rgba(16,185,129,0.25)] flex items-center justify-center"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <LoadingSpinner size="sm" />
                  Generating cryptographic credentials…
                </span>
              ) : (
                'Register Into Trust Chain'
              )}
            </button>
          </form>

          <p className="text-center text-xs text-slate-400 mt-6 font-mono">
            Already authorized?{' '}
            <Link to="/login" className="text-emerald-400 hover:underline">
              Access Terminal
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
