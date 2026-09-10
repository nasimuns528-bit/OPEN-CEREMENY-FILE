/**
 * Admin — User Management Page
 * Lists all users, allows role change and activate/deactivate.
 */
import React, { useEffect, useState } from 'react'
import api from '../api/axios'
import LoadingSpinner from '../components/LoadingSpinner'

const ROLES = ['ADMIN', 'DATA_CONTRIBUTOR', 'MODEL_CONTRIBUTOR', 'REVIEWER', 'INFERENCE_USER']

const ROLE_LABELS = {
  ADMIN: 'Admin',
  DATA_CONTRIBUTOR: 'Data Contributor',
  MODEL_CONTRIBUTOR: 'Model Contributor',
  REVIEWER: 'Reviewer',
  INFERENCE_USER: 'Inference User',
}

const ROLE_COLORS = {
  ADMIN: 'text-red-400',
  DATA_CONTRIBUTOR: 'text-cyan-400',
  MODEL_CONTRIBUTOR: 'text-violet-400',
  REVIEWER: 'text-amber-400',
  INFERENCE_USER: 'text-emerald-400',
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(null)
  const [error, setError] = useState('')

  const fetchUsers = async () => {
    try {
      const { data } = await api.get('/users/')
      setUsers(data)
    } catch {
      setError('Failed to load users.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchUsers() }, [])

  const handleRoleChange = async (userId, newRole) => {
    setUpdating(userId)
    try {
      const { data } = await api.patch(`/users/${userId}`, { role: newRole })
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...data } : u)))
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update role.')
    } finally {
      setUpdating(null)
    }
  }

  const handleToggleActive = async (userId, currentActive) => {
    setUpdating(userId)
    try {
      const { data } = await api.patch(`/users/${userId}`, { is_active: !currentActive })
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...data } : u)))
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update status.')
    } finally {
      setUpdating(null)
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-100">User Management</h1>
        <p className="text-gray-500 text-sm mt-1">Manage roles and account status — Admin only</p>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-700/50 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="card p-0 overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-12"><LoadingSpinner /></div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 border-b border-gray-800">
              <tr>
                <th className="text-left px-6 py-3 text-gray-400 font-medium">User</th>
                <th className="text-left px-6 py-3 text-gray-400 font-medium">Role</th>
                <th className="text-left px-6 py-3 text-gray-400 font-medium">Status</th>
                <th className="text-left px-6 py-3 text-gray-400 font-medium">Joined</th>
                <th className="text-right px-6 py-3 text-gray-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-gray-800/30 transition-colors">
                  <td className="px-6 py-4">
                    <p className="font-medium text-gray-200">{u.username}</p>
                    <p className="text-xs text-gray-600 mt-0.5">{u.email}</p>
                  </td>
                  <td className="px-6 py-4">
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      disabled={updating === u.id}
                      className="bg-gray-800 border border-gray-700 text-gray-200 text-xs
                                 rounded-lg px-2 py-1 focus:outline-none focus:ring-1 focus:ring-brand-500"
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`text-xs font-medium ${u.is_active ? 'text-green-400' : 'text-red-400'}`}>
                      {u.is_active ? '● Active' : '● Inactive'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-xs text-gray-500">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 text-right">
                    {updating === u.id ? (
                      <LoadingSpinner size="sm" className="ml-auto" />
                    ) : (
                      <button
                        onClick={() => handleToggleActive(u.id, u.is_active)}
                        className={`text-xs font-medium px-2.5 py-1 rounded-lg border transition-colors ${
                          u.is_active
                            ? 'border-red-700/50 text-red-400 hover:bg-red-900/20'
                            : 'border-green-700/50 text-green-400 hover:bg-green-900/20'
                        }`}
                      >
                        {u.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
