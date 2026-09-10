/**
 * Phase 8 — Controlled Integrity Attack Demonstration Console.
 * Non-offensive simulation environment operating strictly on local test assets.
 * Demonstrates real-time detection of:
 * 1. Dataset File Tampering -> DATA INTEGRITY FAILURE
 * 2. Model Weights Tampering -> MODEL INTEGRITY FAILURE & INFERENCE BLOCKED
 * 3. Inference Evidence Tampering -> INFERENCE EVIDENCE INVALID
 * 4. Audit Chain Tampering -> AUDIT CHAIN INVALID
 */
import React, { useState } from 'react'
import api from '../api/axios'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

const SCENARIOS = [
  {
    id: 'attack_1_dataset',
    endpoint: '/demonstration/attack-1-dataset-tamper',
    name: 'ATTACK 1: DATASET TAMPERING',
    target: 'Dataset File Storage & SHA-256 Digest',
    expectedBanner: 'DATA INTEGRITY FAILURE',
    bannerStyle: 'bg-red-950/60 border-red-800 text-red-300',
    description:
      'Creates a trusted test dataset, calculates baseline SHA-256, modifies bytes on disk, and recalculates hashes to prove composite verification detects unauthorized tampering.',
    icon: '🗄️',
  },
  {
    id: 'attack_2_model',
    endpoint: '/demonstration/attack-2-model-tamper',
    name: 'ATTACK 2: MODEL WEIGHTS TAMPERING',
    target: 'Model Weights Binary & Pre-Inference Check',
    expectedBanner: 'MODEL INTEGRITY FAILURE // INFERENCE BLOCKED',
    bannerStyle: 'bg-red-950/60 border-red-800 text-red-300',
    description:
      'Registers and approves a clean model artifact with Ed25519 signature, modifies the weights on disk, and proves that pre-inference eligibility verification blocks inference execution.',
    icon: '🧠',
  },
  {
    id: 'attack_3_inference',
    endpoint: '/demonstration/attack-3-inference-tamper',
    name: 'ATTACK 3: INFERENCE OUTPUT TAMPERING',
    target: 'Canonical Evidence JSON & Database Record',
    expectedBanner: 'INFERENCE EVIDENCE INVALID',
    bannerStyle: 'bg-amber-950/60 border-amber-800 text-amber-300',
    description:
      'Executes verified inference with canonical Ed25519 evidence, forges bounding box predictions directly in the database record, and runs 5-pillar verification to catch the tampering.',
    icon: '⚡',
  },
  {
    id: 'attack_4_audit',
    endpoint: '/demonstration/attack-4-audit-tamper',
    name: 'ATTACK 4: AUDIT HASH CHAIN TAMPERING',
    target: 'Append-Only Cryptographic Chain Linkage',
    expectedBanner: 'AUDIT CHAIN INVALID',
    bannerStyle: 'bg-purple-950/60 border-purple-800 text-purple-300',
    description:
      'Appends sequential audit events, modifies a historical event payload directly in the database, and traverses the SHA-256 chain from Genesis to pinpoint the broken linkage.',
    icon: '⛓️',
  },
]

export default function DemonstrationPage() {
  const { user, role, isAdmin, isReviewer } = useAuth()
  const [runningId, setRunningId] = useState(null)
  const [results, setResults] = useState({})
  const [errorMsg, setErrorMsg] = useState('')

  const handleRunAttack = async (scenario) => {
    setRunningId(scenario.id)
    setErrorMsg('')

    try {
      const { data } = await api.post(scenario.endpoint)
      setResults((prev) => ({ ...prev, [scenario.id]: data }))
    } catch (err) {
      setErrorMsg(
        err.response?.data?.detail || `Demonstration '${scenario.name}' failed to execute.`
      )
    } finally {
      setRunningId(null)
    }
  }

  const isAuthorized = isAdmin || isReviewer

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400">CONTROLLED_ENVIRONMENT //</span>
            <span className="text-xs font-mono text-slate-400">ISOLATED TEST ASSETS ONLY</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-wider text-slate-100 flex items-center gap-2">
            <span>🎯</span> CONTROLLED INTEGRITY ATTACK SIMULATOR
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1 max-w-3xl">
            Non-offensive simulation environment demonstrating VisionTrust's cryptographic tamper detection mechanisms.
            All scenarios operate exclusively on synthetic, isolated local test assets without external interaction.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
            CLEARANCE: {role}
          </span>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 text-xs font-mono">
          ⚠️ {errorMsg}
        </div>
      )}

      {!isAuthorized && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/60 rounded-xl text-amber-300 text-xs font-mono">
          ⚠️ Notice: Controlled integrity attack demonstrations require ADMIN or REVIEWER clearance.
        </div>
      )}

      {/* 4 Attack Demonstration Scenario Cards */}
      <div className="grid grid-cols-1 gap-6">
        {SCENARIOS.map((sc) => {
          const res = results[sc.id]
          const isRunning = runningId === sc.id

          return (
            <div
              key={sc.id}
              className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors space-y-4 shadow-sm"
            >
              {/* Card Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
                <div className="flex items-start gap-3">
                  <span className="text-3xl p-2 rounded-xl bg-slate-950 border border-slate-800">
                    {sc.icon}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider">
                        {sc.name}
                      </h2>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        {sc.target}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-400 mt-1 max-w-2xl leading-relaxed">
                      {sc.description}
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => handleRunAttack(sc)}
                  disabled={isRunning || !isAuthorized}
                  className="px-4 py-2 text-xs font-mono font-bold rounded-lg bg-red-900/80 hover:bg-red-800 text-red-100 border border-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 whitespace-nowrap shadow-[0_0_15px_rgba(239,68,68,0.15)]"
                >
                  {isRunning ? (
                    <>
                      <LoadingSpinner size="sm" />
                      <span>SIMULATING TAMPERING...</span>
                    </>
                  ) : (
                    <>
                      <span>⚡</span>
                      <span>RUN CONTROLLED DEMONSTRATION</span>
                    </>
                  )}
                </button>
              </div>

              {/* Real-time Display Result */}
              {res && (
                <div className="space-y-4 pt-2">
                  {/* Big Display Banner */}
                  <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${sc.bannerStyle} shadow-inner`}>
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 block font-bold">
                        DETECTION SYSTEM STATUS:
                      </span>
                      <p className="text-xl font-mono font-black mt-0.5 tracking-wide">
                        🚨 {res.display_title}
                        {res.inference_status && (
                          <span className="ml-3 text-sm px-2 py-0.5 rounded bg-slate-950/80 border border-current font-mono">
                            {res.inference_status}
                          </span>
                        )}
                      </p>
                    </div>
                    <span className="text-xs font-mono px-3 py-1 rounded bg-slate-950/80 border border-current font-bold uppercase self-start sm:self-auto">
                      {res.tamper_detected ? 'TAMPER DETECTED' : 'CLEAN'}
                    </span>
                  </div>

                  {/* Execution Timeline Steps */}
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block font-bold">
                      EXECUTION AUDIT LOG ({res.steps.length} STEPS):
                    </span>
                    <div className="space-y-1.5 font-mono text-xs">
                      {res.steps.map((st) => (
                        <div
                          key={st.step_number}
                          className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-start justify-between gap-2"
                        >
                          <div className="flex items-start gap-2.5">
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                              #{st.step_number}
                            </span>
                            <div>
                              <span className="text-slate-200 font-bold">{st.action}</span>
                              <p className="text-slate-400 text-[11px] mt-0.5">{st.details}</p>
                            </div>
                          </div>
                          <span
                            className={`text-[9px] px-2 py-0.5 rounded border font-bold uppercase whitespace-nowrap ${
                              st.status === 'SUCCESS'
                                ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                                : st.status === 'TAMPER_DETECTED'
                                ? 'bg-red-950 text-red-400 border-red-800'
                                : st.status === 'BLOCKED'
                                ? 'bg-orange-950 text-orange-400 border-orange-800'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                          >
                            {st.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Cryptographic Telemetry Grid */}
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1 text-[11px] font-mono">
                    <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">
                      CRYPTOGRAPHIC TELEMETRY RECORD:
                    </span>
                    {Object.entries(res.telemetry).map(([k, v]) => (
                      <div key={k} className="flex flex-col sm:flex-row sm:items-baseline gap-1">
                        <span className="text-slate-500 text-[10px] uppercase min-w-[200px]">
                          {k.replace(/_/g, ' ')}:
                        </span>
                        <span className="text-slate-200 select-all break-all">
                          {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}