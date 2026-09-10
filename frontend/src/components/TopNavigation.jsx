import React, { useEffect, useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import api from '../api/axios'

export default function TopNavigation({ toggleSidebar }) {
  const { user, role } = useAuth()
  const [apiStatus, setApiStatus] = useState('checking')

  useEffect(() => {
    api.get('/health')
      .then(() => setApiStatus('online'))
      .catch(() => setApiStatus('offline'))
  }, [])

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between h-16 px-6 bg-slate-950/80 backdrop-blur border-b border-slate-800">
      <div className="flex items-center space-x-4">
        <button
          onClick={toggleSidebar}
          className="p-2 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 lg:hidden"
        >
          ☰
        </button>
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-500">Node</span>
          <span className="text-xs font-mono font-medium text-slate-300">alpha-us-east-1</span>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Status Indicators */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            <span
              className={`w-2 h-2 rounded-full ${
                apiStatus === 'online'
                  ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]'
                  : apiStatus === 'offline'
                  ? 'bg-red-400'
                  : 'bg-amber-400 animate-pulse'
              }`}
            />
            <span className="text-slate-300">API: {apiStatus.toUpperCase()}</span>
          </div>

          <div className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            <span className="text-slate-300">CHAIN: SHA-256</span>
          </div>
        </div>

        {/* User profile pill */}
        {user && (
          <div className="flex items-center space-x-2 pl-3 border-l border-slate-800">
            <span className="text-xs font-medium text-slate-300 hidden md:inline">{user.email}</span>
            <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-emerald-400 border border-slate-700">
              {role}
            </span>
          </div>
        )}
      </div>
    </header>
  )
}
