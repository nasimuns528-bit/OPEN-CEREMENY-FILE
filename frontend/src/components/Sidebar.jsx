import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'

const ROLE_BADGES = {
  ADMIN: { label: 'ADMIN', color: 'bg-red-900/60 text-red-300 border-red-700' },
  DATA_CONTRIBUTOR: { label: 'DATA CONTRIB', color: 'bg-blue-900/60 text-blue-300 border-blue-700' },
  MODEL_CONTRIBUTOR: { label: 'MODEL CONTRIB', color: 'bg-indigo-900/60 text-indigo-300 border-indigo-700' },
  REVIEWER: { label: 'REVIEWER', color: 'bg-amber-900/60 text-amber-300 border-amber-700' },
  INFERENCE_USER: { label: 'INFERENCE', color: 'bg-emerald-900/60 text-emerald-300 border-emerald-700' },
}

export default function Sidebar({ isOpen, setIsOpen }) {
  const { user, role, isAdmin, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const roleInfo = ROLE_BADGES[role] || { label: role || 'USER', color: 'bg-gray-800 text-gray-300 border-gray-700' }

  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: '📊' },
    { to: '/datasets', label: 'Datasets & Files', icon: '📁' },
    { to: '/models', label: 'Model Registry', icon: '🧠' },
    { to: '/inference', label: 'Inference & Verify', icon: '⚡' },
    { to: '/audit', label: 'Audit Trail', icon: '⛓️' },
    { to: '/demonstration', label: 'Attack Simulator', icon: '🎯' },
  ]

  if (isAdmin) {
    navItems.push({ to: '/admin/users', label: 'User Governance', icon: '🛡️' })
  }

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex flex-col bg-slate-950 border-r border-slate-800 transition-all duration-300 ease-in-out ${
        isOpen ? 'w-64' : 'w-20'
      }`}
    >
      {/* Brand Header */}
      <div className="flex items-center justify-between h-16 px-4 border-b border-slate-800 bg-slate-900/50">
        <div className="flex items-center space-x-3 overflow-hidden">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-black text-xl shadow-[0_0_15px_rgba(16,185,129,0.2)]">
            VT
          </div>
          {isOpen && (
            <div className="flex flex-col">
              <span className="font-bold tracking-wider text-slate-100 text-base">VISIONTRUST</span>
              <span className="text-[10px] font-mono tracking-widest text-emerald-400">INTEGRITY ASSURED</span>
            </div>
          )}
        </div>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/60"
          title={isOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        >
          {isOpen ? '◀' : '▶'}
        </button>
      </div>

      {/* User Badge */}
      {user && (
        <div className="p-3 mx-2 my-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-slate-200 text-xs">
              {user.username.slice(0, 2).toUpperCase()}
            </div>
            {isOpen && (
              <div className="flex flex-col min-w-0">
                <span className="text-sm font-medium text-slate-200 truncate">{user.username}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border inline-block w-max mt-0.5 ${roleInfo.color}`}>
                  {roleInfo.label}
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 px-2 py-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`
            }
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="ml-3 truncate">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer / Logout */}
      <div className="p-3 border-t border-slate-800 bg-slate-900/30">
        <button
          onClick={handleLogout}
          className="w-full flex items-center px-3 py-2 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 rounded-lg transition-colors"
        >
          <span>🚪</span>
          {isOpen && <span className="ml-3">Sign Out</span>}
        </button>
      </div>
    </aside>
  )
}
