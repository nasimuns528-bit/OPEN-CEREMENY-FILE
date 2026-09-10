/**
 * NavBar — top navigation bar with role-aware links and logout.
 */
import React, { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'

const ROLE_BADGE = {
  admin:       'badge-admin',
  contributor: 'badge-contributor',
  viewer:      'badge-viewer',
}

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `text-sm font-medium px-3 py-2 rounded-lg transition-colors duration-150 ${
          isActive
            ? 'bg-brand-900/50 text-brand-400'
            : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
        }`
      }
    >
      {children}
    </NavLink>
  )
}

export default function NavBar() {
  const { user, logout, isAdmin, isContributor } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <nav className="sticky top-0 z-50 bg-gray-950/95 backdrop-blur border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <Link to="/dashboard" className="flex items-center gap-2.5 group">
            <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center
                            group-hover:bg-brand-500 transition-colors">
              <span className="text-white font-bold text-sm">VT</span>
            </div>
            <span className="font-semibold text-gray-100 text-base hidden sm:block">
              Vision<span className="text-brand-500">Trust</span>
            </span>
          </Link>

          {/* Desktop nav links */}
          <div className="hidden md:flex items-center gap-1">
            <NavItem to="/dashboard">Dashboard</NavItem>
            {isContributor && <NavItem to="/datasets">Datasets</NavItem>}
            {isContributor && <NavItem to="/models">Models</NavItem>}
            {isContributor && <NavItem to="/inference">Inference</NavItem>}
            {isAdmin && <NavItem to="/audit">Audit Log</NavItem>}
            {isAdmin && <NavItem to="/admin/users">Users</NavItem>}
          </div>

          {/* User info + logout */}
          <div className="flex items-center gap-3">
            {user && (
              <>
                <div className="hidden sm:flex items-center gap-2">
                  <span className="text-sm text-gray-400">{user.username}</span>
                  <span className={ROLE_BADGE[user.role]}>{user.role}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="btn-secondary text-xs px-3 py-1.5"
                >
                  Sign Out
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  )
}
