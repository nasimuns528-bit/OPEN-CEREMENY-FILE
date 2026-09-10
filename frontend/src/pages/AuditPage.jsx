import React, { useEffect, useState } from 'react'
import api from '../api/axios'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

const PAGE_SIZE = 25

export default function AuditPage() {
  const { isReviewer, isAdmin } = useAuth()
  const canVerify = isReviewer || isAdmin

  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [actionFilter, setActionFilter] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [page, setPage] = useState(0)

  const fetchEvents = async () => {
    try {
      setLoading(true)
      const params = actionFilter ? { action: actionFilter, limit: 200 } : { limit: 200 }
      const { data } = await api.get('/audit', { params })
      setEvents(data)
      setPage(0)
    } catch (err) {
      setErrorMsg('Failed to load audit events.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEvents()
  }, [actionFilter])

  const totalPages = Math.ceil(events.length / PAGE_SIZE)
  const pagedEvents = events.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE)

  const handleVerifyChain = async () => {
    setVerifying(true)
    setErrorMsg('')
    try {
      const { data } = await api.post('/audit/verify')
      setVerifyResult(data)
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Chain verification failed.')
    } finally {
      setVerifying(false)
    }
  }

  const getActionColor = (action) => {
    if (action.includes('TAMPER')) return 'bg-red-950 text-red-400 border-red-800'
    if (action.includes('VERIFIED')) return 'bg-cyan-950 text-cyan-400 border-cyan-800'
    if (action.includes('CREATED') || action.includes('UPLOADED')) return 'bg-emerald-950 text-emerald-400 border-emerald-800'
    if (action.includes('login') || action.includes('register')) return 'bg-blue-950 text-blue-400 border-blue-800'
    return 'bg-slate-900 text-slate-400 border-slate-700'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-wider text-slate-100 flex items-center gap-2">
            <span>⛓️</span> MULTI-CONTRIBUTOR PROVENANCE & AUDIT CHAIN
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Application-level tamper-evident SHA-256 hash chain · Complete state transition tracking
          </p>
        </div>
        {canVerify && (
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs transition-colors shadow-[0_0_15px_rgba(16,185,129,0.25)] flex items-center gap-2"
          >
            {verifying ? <LoadingSpinner size="sm" /> : '🔒 VERIFY COMPLETE CHAIN'}
          </button>
        )}
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 text-xs font-mono">
          [ERROR] {errorMsg}
        </div>
      )}

      {/* Chain Health Status Banner */}
      {verifyResult && (
        <div
          className={`p-4 rounded-xl border font-mono text-xs space-y-2 ${
            verifyResult.valid
              ? 'bg-emerald-950/40 border-emerald-500/60 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.15)]'
              : 'bg-red-950/40 border-red-500/80 text-red-300 shadow-[0_0_20px_rgba(239,68,68,0.2)]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-bold text-sm flex items-center gap-2">
              {verifyResult.valid ? '✅ AUDIT CHAIN INTEGRITY SECURE' : '⚠️ AUDIT CHAIN COMPROMISED'}
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded border border-current">
              {verifyResult.events_checked} EVENTS SCANNED
            </span>
          </div>
          {verifyResult.valid ? (
            <div>
              Chain Head Digest:{' '}
              <span className="text-emerald-400 select-all font-bold">
                {verifyResult.chain_head_hash || 'N/A'}
              </span>
            </div>
          ) : (
            <div className="space-y-1 text-red-400">
              <div>Detected tampering: {verifyResult.tamper_details}</div>
              <div>First corrupted event ID: <span className="underline select-all">{verifyResult.first_invalid_event}</span></div>
            </div>
          )}
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/40 border border-slate-800 p-3 rounded-xl">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">ACTION FILTER:</span>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono rounded-lg px-2.5 py-1 focus:outline-none focus:border-emerald-500"
          >
            <option value="">ALL ACTIONS</option>
            <option value="DATASET_CREATED">DATASET_CREATED</option>
            <option value="FILE_UPLOADED">FILE_UPLOADED</option>
            <option value="DATASET_VERSION_CREATED">DATASET_VERSION_CREATED</option>
            <option value="DATASET_VERIFIED">DATASET_VERIFIED</option>
            <option value="DATASET_TAMPER_DETECTED">DATASET_TAMPER_DETECTED</option>
            <option value="user.login">USER_LOGIN</option>
            <option value="user.register">USER_REGISTER</option>
          </select>
        </div>
        <button
          onClick={fetchEvents}
          className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
        >
          🔄 Refresh
        </button>
      </div>

      {/* Events Log Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex justify-center p-12"><LoadingSpinner /></div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No audit records matching query.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-3">Seq #</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Actor</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Asset / Target</th>
                  <th className="px-4 py-3">Transition</th>
                  <th className="px-4 py-3">Hash Linkage</th>
                  <th className="px-4 py-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {pagedEvents.map((ev) => (

                  <tr key={ev.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 text-emerald-400 font-bold">#{ev.sequence_number}</td>
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-slate-200 font-medium">{ev.actor_username || 'SYSTEM'}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded border ${getActionColor(ev.action)}`}>
                        {ev.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {ev.resource_type ? `${ev.resource_type}:${ev.resource_id?.slice(0, 8)}...` : 'N/A'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {ev.previous_state || ev.new_state ? (
                        <span>
                          <span className="text-slate-500">{ev.previous_state || 'None'}</span>
                          <span className="text-emerald-500 mx-1">→</span>
                          <span className="text-slate-200 font-semibold">{ev.new_state || 'None'}</span>
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-[10px]">
                      <div className="text-slate-500 truncate w-32" title={ev.previous_event_hash || 'GENESIS'}>
                        prev: {ev.previous_event_hash?.slice(0, 8) || 'GENESIS'}...
                      </div>
                      <div className="text-emerald-400/90 truncate w-32" title={ev.current_hash}>
                        curr: {ev.current_hash.slice(0, 8)}...
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="text-xs text-slate-400 hover:text-emerald-400 border border-slate-700 hover:border-emerald-500/50 rounded px-2 py-1 transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-2 py-3 text-xs font-mono">
          <span className="text-slate-500">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, events.length)} of {events.length} events
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              ← Prev
            </button>
            <span className="text-slate-400 px-2">
              Page {page + 1} / {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}

      {/* Inspector Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-slate-100">
                AUDIT RECORD #{selectedEvent.sequence_number}
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px]">EVENT ID</span>
                <span className="text-slate-200 select-all">{selectedEvent.id}</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 block text-[10px]">ACTOR</span>
                  <span className="text-slate-200">{selectedEvent.actor_username || 'SYSTEM'} ({selectedEvent.actor_id || 'N/A'})</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">IP ADDRESS</span>
                  <span className="text-slate-200">{selectedEvent.ip_address || 'Internal'}</span>
                </div>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">ACTION</span>
                <span className="text-emerald-400 font-bold">{selectedEvent.action}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">PREVIOUS EVENT HASH (SHA-256)</span>
                <span className="text-slate-400 select-all break-all">{selectedEvent.previous_event_hash || 'GENESIS_ROOT'}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">CURRENT EVENT HASH (SHA-256)</span>
                <span className="text-emerald-400 select-all break-all">{selectedEvent.current_hash}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">METADATA / CONTEXT JSON</span>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-[11px] overflow-x-auto">
                  {selectedEvent.details
                    ? JSON.stringify(JSON.parse(selectedEvent.details), null, 2)
                    : 'None'}
                </pre>
              </div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg transition-colors"
              >
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
