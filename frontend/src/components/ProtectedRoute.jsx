/**
 * ProtectedRoute — redirects to /login if user is not authenticated.
 * Optionally enforces role-based access with `allowedRoles` (array of role strings).
 * ADMIN role always has access to every protected route.
 */
import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from './LoadingSpinner'

const ROLE_LABELS = {
  ADMIN: 'Admin',
  DATA_CONTRIBUTOR: 'Data Contributor',
  MODEL_CONTRIBUTOR: 'Model Contributor',
  REVIEWER: 'Reviewer',
  INFERENCE_USER: 'Inference User',
}

export default function ProtectedRoute({ children, allowedRoles }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  // Normalize role for comparison
  const userRole = (user.role || '').toUpperCase()

  // If allowedRoles specified, check membership. ADMIN always passes.
  if (allowedRoles && allowedRoles.length > 0) {
    const normalizedAllowed = allowedRoles.map((r) => r.toUpperCase())
    if (userRole !== 'ADMIN' && !normalizedAllowed.includes(userRole)) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-slate-950">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 max-w-md w-full text-center shadow-lg">
            <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-3xl mx-auto mb-5 shadow-[0_0_20px_rgba(239,68,68,0.15)]">
              🔒
            </div>
            <h2 className="text-xl font-bold text-slate-100 font-mono tracking-wider mb-2">
              ACCESS DENIED
            </h2>
            <p className="text-slate-400 text-sm mb-4">
              This route requires one of:{' '}
              {normalizedAllowed.map((r) => (
                <span key={r} className="text-emerald-400 font-medium font-mono text-xs">
                  {ROLE_LABELS[r] || r}{' '}
                </span>
              ))}
            </p>
            <p className="text-slate-500 text-xs font-mono">
              Your clearance:{' '}
              <span className="text-amber-400">{ROLE_LABELS[userRole] || userRole}</span>
            </p>
          </div>
        </div>
      )
    }
  }

  return children
}
