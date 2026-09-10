import React, { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopNavigation from './TopNavigation'

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Sidebar isOpen={sidebarOpen} setIsOpen={setSidebarOpen} />

      <div
        className={`flex-1 flex flex-col transition-all duration-300 ease-in-out ${
          sidebarOpen ? 'lg:pl-64' : 'lg:pl-20'
        }`}
      >
        <TopNavigation toggleSidebar={() => setSidebarOpen(!sidebarOpen)} />

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          <Outlet />
        </main>

        <footer className="py-4 px-6 border-t border-slate-900 text-center text-xs text-slate-600 font-mono">
          VISIONTRUST SECURITY PROTOCOL v1.0.0 · ZERO-TRUST CRYPTOGRAPHIC PROVENANCE
        </footer>
      </div>
    </div>
  )
}
