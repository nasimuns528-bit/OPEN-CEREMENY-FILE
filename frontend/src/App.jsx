/**
 * App — root router with Layout (Sidebar + TopNavigation) and protected routes.
 * Uses React Router v6 nested routes with Layout's <Outlet />.
 */
import React from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'

// Pages
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import AdminUsersPage from './pages/AdminUsersPage'
import NotFoundPage from './pages/NotFoundPage'
import DatasetsPage from './pages/DatasetsPage'
import AuditPage from './pages/AuditPage'
import ModelsPage from './pages/ModelsPage'
import InferencePage from './pages/InferencePage'
import DemonstrationPage from './pages/DemonstrationPage'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public routes — no layout, full-screen pages */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected routes — wrapped in Layout (Sidebar + TopNav) */}
          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            {/* Dashboard — any authenticated user */}
            <Route path="/dashboard" element={<DashboardPage />} />

            {/* Datasets — all authenticated users can view; upload restricted by role */}
            <Route path="/datasets" element={<DatasetsPage />} />

            {/* Models Registry — all authenticated users can view; upload & approve restricted by role */}
            <Route path="/models" element={<ModelsPage />} />

            {/* Inference Engine — all authenticated users can run inference & inspect evidence */}
            <Route path="/inference" element={<InferencePage />} />

            {/* Audit Trail — all authenticated users can view; chain verification restricted to Reviewer/Admin */}
            <Route path="/audit" element={<AuditPage />} />

            {/* Controlled Integrity Attack Simulator — Admin and Reviewers */}
            <Route path="/demonstration" element={<DemonstrationPage />} />

            {/* Admin-only routes */}
            <Route
              path="/admin/users"
              element={
                <ProtectedRoute allowedRoles={['ADMIN']}>
                  <AdminUsersPage />
                </ProtectedRoute>
              }
            />
          </Route>

          {/* Default redirect */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          {/* 404 — catch-all */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
