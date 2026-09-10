import React from 'react'
import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6 text-center">
      <div className="w-20 h-20 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-4xl mb-6 shadow-[0_0_30px_rgba(239,68,68,0.2)]">
        🛡️
      </div>

      <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-amber-400 font-mono mb-2">
        404
      </h1>

      <h2 className="text-xl font-bold text-slate-100 tracking-wider font-mono mb-3">
        ACCESS VECTOR NOT FOUND
      </h2>

      <p className="text-slate-400 text-sm max-w-md mb-8">
        The requested routing node does not exist or your security clearance does not allow traversal along this path.
      </p>

      <div className="flex flex-col sm:flex-row gap-4">
        <Link
          to="/dashboard"
          className="px-6 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm transition-colors shadow-[0_0_20px_rgba(16,185,129,0.3)]"
        >
          Return to Dashboard
        </Link>
        <Link
          to="/login"
          className="px-6 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 font-medium text-sm transition-colors"
        >
          Sign In
        </Link>
      </div>

      <div className="mt-12 text-[11px] font-mono text-slate-600">
        ERROR_CODE: ERR_VT_UNRESOLVED_ROUTE_TARGET
      </div>
    </div>
  )
}
