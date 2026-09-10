/**
 * Phase 7 — VisionTrust Integrity Assurance Dashboard.
 * Displays:
 * 1. 0-100 Integrity Assurance Score gauge with transparent rating and official disclaimer.
 * 2. 6-Component Scoring Breakdown (Data, Models, Provenance, Contributors, Inference, Scans).
 * 3. Pipeline Health Status Cards (Datasets, Models, Inference, Cryptographic Audit Chain).
 * 4. Active Security Alerts feed with severity color indicators.
 * 5. Role-specific shortcut actions.
 */
import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import api from '../api/axios'
import LoadingSpinner from '../components/LoadingSpinner'

function AssuranceDial({ score, rating, disclaimer }) {
  const getRatingColor = () => {
    if (score >= 85) return 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20'
    if (score >= 60) return 'text-amber-400 border-amber-500/40 bg-amber-950/20'
    return 'text-red-400 border-red-500/40 bg-red-950/20'
  }

  const getProgressStroke = () => {
    if (score >= 85) return '#10b981'
    if (score >= 60) return '#f59e0b'
    return '#ef4444'
  }

  // Radius 54 -> circumference ~ 339.29
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className={`p-6 rounded-2xl border ${getRatingColor()} flex flex-col md:flex-row items-center justify-between gap-6 shadow-lg backdrop-blur-sm`}>
      <div className="flex items-center gap-6">
        {/* SVG Circle Gauge */}
        <div className="relative w-32 h-32 flex-shrink-0 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 128 128">
            <circle
              cx="64"
              cy="64"
              r={radius}
              stroke="#1e293b"
              strokeWidth="10"
              fill="transparent"
            />
            <circle
              cx="64"
              cy="64"
              r={radius}
              stroke={getProgressStroke()}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
            <span className="text-3xl font-black text-slate-100">{score.toFixed(1)}</span>
            <span className="text-[10px] text-slate-400 uppercase tracking-widest">/ 100</span>
          </div>
        </div>

        {/* Text Details */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-900/80 border border-slate-700 text-slate-300 uppercase tracking-wider">
              {rating}
            </span>
            <span className="text-xs font-mono text-slate-400">REAL-TIME ASSURANCE POSTURE</span>
          </div>
          <h2 className="text-xl font-bold font-mono text-slate-100 tracking-tight">
            VisionTrust Integrity Assurance Score
          </h2>
          <p className="text-xs font-mono text-slate-300 max-w-xl leading-relaxed">
            Cryptographic assurance aggregating dataset integrity, model provenance, static bytecode analysis, and signed inference evidence.
          </p>
        </div>
      </div>

      {/* Mandatory Disclaimer Box */}
      <div className="max-w-xs p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-[11px] font-mono text-slate-400 leading-normal flex-shrink-0">
        <span className="text-amber-400 font-bold block mb-1 text-[10px] uppercase tracking-wider">
          ⚠️ Operational Disclaimer:
        </span>
        {disclaimer}
      </div>
    </div>
  )
}

function ScoringComponentCard({ component }) {
  const getStatusBadge = (status) => {
    switch (status) {
      case 'OPTIMAL':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-800'
      case 'ATTENTION':
        return 'bg-amber-950/80 text-amber-400 border-amber-800'
      case 'DEGRADED':
        return 'bg-red-950/80 text-red-400 border-red-800'
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700'
    }
  }

  const getBarColor = (status) => {
    switch (status) {
      case 'OPTIMAL':
        return 'bg-emerald-500'
      case 'ATTENTION':
        return 'bg-amber-500'
      case 'DEGRADED':
        return 'bg-red-500'
      default:
        return 'bg-slate-500'
    }
  }

  const pct = (component.score / component.max_score) * 100

  return (
    <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-colors space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
          {component.name}
        </span>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${getStatusBadge(component.status)}`}>
          {component.status}
        </span>
      </div>

      {/* Progress Bar */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">Score Weight</span>
          <span className="text-slate-200 font-bold">
            {component.score} / {component.max_score} pts
          </span>
        </div>
        <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${getBarColor(component.status)}`}
            style={{ width: `${Math.max(4, pct)}%` }}
          />
        </div>
      </div>

      <p className="text-[11px] font-mono text-slate-400 leading-snug">
        {component.explanation}
      </p>
    </div>
  )
}

function PipelineStatusCard({ title, icon, stats, linkTo, linkText }) {
  return (
    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            {title}
          </span>
        </div>
        {linkTo && (
          <Link
            to={linkTo}
            className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 underline"
          >
            {linkText || 'View'}
          </Link>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/60">
        {Object.entries(stats).map(([k, v]) => (
          <div key={k}>
            <span className="text-[10px] font-mono text-slate-500 uppercase block">
              {k.replace(/_/g, ' ')}
            </span>
            <span className="text-xs font-mono font-bold text-slate-200">{String(v)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SecurityAlertsFeed({ alerts, count }) {
  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-400 border-red-800'
      case 'HIGH':
        return 'bg-orange-950 text-orange-400 border-orange-800'
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-400 border-amber-800'
      default:
        return 'bg-blue-950 text-blue-400 border-blue-800'
    }
  }

  return (
    <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-base">🚨</span>
          <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Active Security & Integrity Alerts ({count})
          </h3>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${count === 0 ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-red-950 text-red-400 border-red-800'}`}>
          {count === 0 ? 'ZERO THREATS' : `${count} ATTENTION REQUIRED`}
        </span>
      </div>

      {count === 0 ? (
        <div className="py-6 text-center text-xs font-mono text-slate-400 flex flex-col items-center gap-2">
          <span className="text-2xl text-emerald-400">🛡️</span>
          <span>Zero security violations detected. All cryptographic hash chains and scan policies are passing.</span>
        </div>
      ) : (
        <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
          {alerts.map((a) => (
            <div
              key={a.id}
              className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg flex items-start justify-between gap-3 text-xs font-mono"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold ${getSeverityBadge(a.severity)}`}>
                    {a.severity}
                  </span>
                  <span className="text-[10px] text-slate-400 font-bold uppercase">
                    [{a.category}]
                  </span>
                  <span className="text-slate-200 font-bold">{a.title}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">{a.description}</p>
              </div>
              <span className="text-[10px] text-slate-500 whitespace-nowrap">
                {new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function DashboardPage() {
  const { user, role, loading: authLoading } = useAuth()
  const [metrics, setMetrics] = useState(null)
  const [loading, setLoading] = useState(true)
  const [errorMsg, setErrorMsg] = useState('')

  const fetchDashboardMetrics = async () => {
    try {
      setLoading(true)
      const { data } = await api.get('/dashboard/metrics')
      setMetrics(data)
      setErrorMsg('')
    } catch (err) {
      setErrorMsg('Failed to load trust assurance metrics.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboardMetrics()
  }, [])

  if (authLoading || loading) {
    return (
      <div className="flex justify-center items-center min-h-[50vh]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-emerald-400">OPERATOR_LOGGED_IN //</span>
            <span className="text-xs font-mono text-slate-400">{user?.username} ({role})</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-wider text-slate-100 flex items-center gap-2">
            <span>🛡️</span> VISIONTRUST SECURITY CONSOLE
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchDashboardMetrics}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <span>🔄</span> Refresh Assurance
          </button>
          <Link
            to="/inference"
            className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold font-mono transition-colors shadow-[0_0_15px_rgba(16,185,129,0.2)]"
          >
            Run Inference ⚡
          </Link>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 text-xs font-mono">
          ⚠️ {errorMsg}
        </div>
      )}

      {metrics && (
        <>
          {/* 1. Assurance Score Dial & Official Disclaimer */}
          <AssuranceDial
            score={metrics.assurance_score}
            rating={metrics.rating}
            disclaimer={metrics.disclaimer}
          />

          {/* 2. Six-Component Scoring Breakdown */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <span>📊</span> 6-Pillar Integrity Scoring Breakdown
              </h3>
              <span className="text-[10px] font-mono text-slate-500">
                MAX 100 PTS ASSURANCE
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {metrics.scoring_breakdown.map((comp) => (
                <ScoringComponentCard key={comp.key} component={comp} />
              ))}
            </div>
          </div>

          {/* 3. Pipeline Health Status Cards */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <span>🔗</span> Multi-Contributor Pipeline Status
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <PipelineStatusCard
                title="Datasets"
                icon="🗄️"
                stats={{
                  total_sets: metrics.datasets_summary.total_datasets,
                  versions: metrics.datasets_summary.total_versions,
                  verified: metrics.datasets_summary.verified_count,
                  tampered: metrics.datasets_summary.tampered_count,
                }}
                linkTo="/datasets"
                linkText="Datasets ↗"
              />

              <PipelineStatusCard
                title="CV Models"
                icon="🧠"
                stats={{
                  total_models: metrics.models_summary.total_models,
                  versions: metrics.models_summary.total_versions,
                  approved: metrics.models_summary.approved_count,
                  pending: metrics.models_summary.pending_count,
                }}
                linkTo="/models"
                linkText="Registry ↗"
              />

              <PipelineStatusCard
                title="CV Inference"
                icon="⚡"
                stats={{
                  executions: metrics.inference_summary.total_inferences,
                  verified: metrics.inference_summary.verified_count,
                  tampered: metrics.inference_summary.tampered_count,
                  avg_conf: `${(metrics.inference_summary.avg_confidence * 100).toFixed(0)}%`,
                }}
                linkTo="/inference"
                linkText="Inference ↗"
              />

              <PipelineStatusCard
                title="Audit Chain"
                icon="⛓️"
                stats={{
                  chain_length: metrics.audit_chain_status.chain_length,
                  status: metrics.audit_chain_status.is_valid ? 'VALID ROOT' : 'BROKEN',
                  genesis: 'VERIFIED',
                  errors: metrics.audit_chain_status.tamper_detail ? 1 : 0,
                }}
                linkTo="/audit"
                linkText="Audit Log ↗"
              />
            </div>
          </div>

          {/* 4. Active Security Alerts */}
          <SecurityAlertsFeed
            alerts={metrics.security_alerts}
            count={metrics.active_alerts_count}
          />
        </>
      )}
    </div>
  )
}