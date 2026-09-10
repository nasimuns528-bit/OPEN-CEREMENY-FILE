import React, { useEffect, useRef, useState } from 'react'
import api from '../api/axios'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

const RECORDS_PAGE_SIZE = 20

export default function InferencePage() {
  const { user } = useAuth()

  const [models, setModels] = useState([])
  const [selectedModelId, setSelectedModelId] = useState('')
  const [selectedImage, setSelectedImage] = useState(null)
  const [previewUrl, setPreviewUrl] = useState('')
  const [running, setRunning] = useState(false)
  const [inferenceResult, setInferenceResult] = useState(null)
  const [records, setRecords] = useState([])
  const [loadingRecords, setLoadingRecords] = useState(true)
  const [errorMsg, setErrorMsg] = useState('')
  const [copiedEvidence, setCopiedEvidence] = useState(false)
  const [recordsPage, setRecordsPage] = useState(0)

  // Verification Modal State
  const [verificationModalOpen, setVerificationModalOpen] = useState(false)
  const [verifyingLoading, setVerifyingLoading] = useState(false)
  const [verificationData, setVerificationData] = useState(null)
  const [verifyingId, setVerifyingId] = useState('')


  const canvasRef = useRef(null)

  const fetchApprovedModels = async () => {
    try {
      const { data } = await api.get('/models')
      const approvedOnly = data.filter((m) => m.latest_approval === 'APPROVED')
      setModels(approvedOnly)
      if (approvedOnly.length > 0) {
        setSelectedModelId(approvedOnly[0].id)
      }
    } catch {
      setErrorMsg('Failed to fetch model registry.')
    }
  }

  const fetchInferenceRecords = async () => {
    try {
      setLoadingRecords(true)
      const { data } = await api.get('/inference/records')
      setRecords(data)
    } catch {
      // Non-blocking
    } finally {
      setLoadingRecords(false)
    }
  }

  useEffect(() => {
    fetchApprovedModels()
    fetchInferenceRecords()
  }, [])

  const handleImageSelect = (e) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedImage(file)
      setPreviewUrl(URL.createObjectURL(file))
      setInferenceResult(null)
      setErrorMsg('')
    }
  }

  const handleRunInference = async (e) => {
    e.preventDefault()
    if (!selectedImage || !selectedModelId) return

    setRunning(true)
    setErrorMsg('')
    setInferenceResult(null)

    const formData = new FormData()
    formData.append('model_id', selectedModelId)
    formData.append('image', selectedImage)

    try {
      const { data } = await api.post('/inference/detect', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setInferenceResult(data)
      fetchInferenceRecords()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Inference failed.')
    } finally {
      setRunning(false)
    }
  }

  // Draw bounding boxes on canvas
  useEffect(() => {
    if (!inferenceResult || !previewUrl || !canvasRef.current) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    const img = new Image()
    img.src = previewUrl
    img.onload = () => {
      canvas.width = img.naturalWidth || 600
      canvas.height = img.naturalHeight || 400

      ctx.drawImage(img, 0, 0, canvas.width, canvas.height)

      const colors = ['#10b981', '#06b6d4', '#8b5cf6', '#f59e0b', '#ec4899']
      inferenceResult.predictions.forEach((pred, idx) => {
        const [x1, y1, x2, y2] = pred.bbox
        const color = colors[idx % colors.length]

        ctx.strokeStyle = color
        ctx.lineWidth = 3
        ctx.strokeRect(x1, y1, x2 - x1, y2 - y1)

        ctx.fillStyle = color
        const label = `${pred.class_name} ${(pred.confidence * 100).toFixed(0)}%`
        ctx.font = 'bold 12px monospace'
        const textWidth = ctx.measureText(label).width
        ctx.fillRect(x1, Math.max(0, y1 - 22), textWidth + 8, 20)

        ctx.fillStyle = '#020617'
        ctx.fillText(label, x1 + 4, Math.max(14, y1 - 7))
      })
    }
  }, [inferenceResult, previewUrl])

  const copyEvidenceJSON = () => {
    if (!inferenceResult) return
    navigator.clipboard.writeText(JSON.stringify(inferenceResult, null, 2))
    setCopiedEvidence(true)
    setTimeout(() => setCopiedEvidence(false), 2000)
  }

  // Handle Verify Evidence Record Action
  const handleVerifyEvidence = async (inferenceId) => {
    setVerifyingId(inferenceId)
    setVerifyingLoading(true)
    setVerificationModalOpen(true)
    setVerificationData(null)

    try {
      const { data } = await api.post(`/inference/${inferenceId}/verify`)
      setVerificationData(data)
    } catch (err) {
      setVerificationData({
        inference_id: inferenceId,
        input_integrity: false,
        model_integrity: false,
        provenance_valid: false,
        evidence_integrity: false,
        signature_valid: false,
        overall_status: 'NOT_VERIFIED',
        discrepancies: [err.response?.data?.detail || 'Verification request failed.'],
        timestamp: new Date().toISOString(),
      })
    } finally {
      setVerifyingLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-wider text-slate-100 flex items-center gap-2">
            <span>🔬</span> VERIFIED COMPUTER VISION INFERENCE
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Pre-inference model integrity validation · Object detection · Ed25519 cryptographic evidence records
          </p>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 text-xs font-mono">
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Main Grid: Control Panel + Live Output */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input & Config (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <form onSubmit={handleRunInference} className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4 shadow-sm">
            <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <span>⚙️</span> Inference Configuration
            </h2>

            {/* Model Selection */}
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Select Approved CV Model:
              </label>
              <select
                value={selectedModelId}
                onChange={(e) => setSelectedModelId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                {models.length === 0 ? (
                  <option value="">No approved models available</option>
                ) : (
                  models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.framework}) — {m.latest_version_tag}
                    </option>
                  ))
                )}
              </select>
            </div>

            {/* Image Upload */}
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Input Image Frame:
              </label>
              <input
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleImageSelect}
                className="w-full text-xs font-mono text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-mono file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer"
              />
            </div>

            {/* Image Preview */}
            {previewUrl && (
              <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
                <p className="text-[10px] font-mono text-slate-500 mb-1">INPUT FRAME PREVIEW:</p>
                <img
                  src={previewUrl}
                  alt="Preview"
                  className="w-full max-h-48 object-contain rounded bg-slate-900"
                />
              </div>
            )}

            {/* Run Button */}
            <button
              type="submit"
              disabled={running || !selectedImage || !selectedModelId}
              className="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 text-xs font-mono font-bold rounded-lg transition-colors flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.2)]"
            >
              {running ? (
                <>
                  <LoadingSpinner size="sm" />
                  <span>EXECUTING VERIFIED PIPELINE...</span>
                </>
              ) : (
                <>
                  <span>⚡</span>
                  <span>RUN VERIFIED INFERENCE</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right: Verified CV Output & Evidence (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!inferenceResult && !running && (
            <div className="p-12 border-2 border-dashed border-slate-800 rounded-xl flex flex-col items-center justify-center text-center space-y-2">
              <span className="text-4xl text-slate-700">🖼️</span>
              <p className="text-xs font-mono text-slate-400">
                Upload a frame and trigger inference to view detected objects and cryptographic evidence.
              </p>
            </div>
          )}

          {running && (
            <div className="p-12 bg-slate-900/40 border border-slate-800 rounded-xl flex flex-col items-center justify-center space-y-3">
              <LoadingSpinner size="lg" />
              <p className="text-xs font-mono text-emerald-400 animate-pulse">
                Validating model hash · Scanning integrity · Executing inference...
              </p>
            </div>
          )}

          {inferenceResult && (
            <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
              {/* Output Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                    <span>🛡️</span> {inferenceResult.statement}
                  </span>
                  <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                    ID: {inferenceResult.inference_id}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleVerifyEvidence(inferenceResult.inference_id)}
                    className="px-2.5 py-1 text-xs font-mono bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded transition-colors flex items-center gap-1"
                  >
                    <span>🔍</span> Verify Evidence
                  </button>
                  <button
                    onClick={copyEvidenceJSON}
                    className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
                  >
                    {copiedEvidence ? 'Copied!' : 'Copy Evidence'}
                  </button>
                </div>
              </div>

              {/* Bounding Box Visual Canvas */}
              <div className="relative border border-slate-800 rounded-lg overflow-hidden bg-slate-950 flex justify-center">
                <canvas ref={canvasRef} className="max-w-full max-h-96 object-contain" />
              </div>

              {/* Detections List */}
              <div>
                <p className="text-[10px] font-mono uppercase text-slate-400 mb-2">
                  Object Detections ({inferenceResult.predictions.length}):
                </p>
                <div className="flex flex-wrap gap-2">
                  {inferenceResult.predictions.map((p, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1.5"
                    >
                      <span className="font-bold text-emerald-400">{p.class_name}</span>
                      <span className="text-[10px] text-slate-400">
                        {(p.confidence * 100).toFixed(0)}%
                      </span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Cryptographic Hashes Grid */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">INPUT IMAGE DIGEST (SHA-256):</span>
                  <span className="text-slate-200 select-all break-all">{inferenceResult.input_hash}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">MODEL WEIGHTS DIGEST (SHA-256):</span>
                  <span className="text-slate-200 select-all break-all">{inferenceResult.model_hash}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">OUTPUT EVIDENCE CANONICAL DIGEST (SHA-256):</span>
                  <span className="text-emerald-400 select-all break-all font-bold">{inferenceResult.output_hash}</span>
                </div>
                {inferenceResult.evidence_signature && (
                  <div>
                    <span className="text-cyan-400 block text-[10px]">ED25519 ASYMMETRIC EVIDENCE SIGNATURE:</span>
                    <span className="text-cyan-300 select-all break-all font-mono font-bold">
                      {inferenceResult.evidence_signature}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Historical Inference Evidence Records Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden mt-8">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono font-bold text-slate-300 uppercase">
            Historical Inference Evidence Log ({records.length})
          </span>
          <button
            onClick={fetchInferenceRecords}
            className="text-xs font-mono text-slate-400 hover:text-slate-200"
          >
            🔄 Refresh
          </button>
        </div>
        {loadingRecords ? (
          <div className="flex justify-center p-8"><LoadingSpinner /></div>
        ) : records.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No inference records executed yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">File</th>
                  <th className="px-4 py-3">Model</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Top Conf</th>
                  <th className="px-4 py-3">Evidence Hash</th>
                  <th className="px-4 py-3">Executor</th>
                  <th className="px-4 py-3 text-right">Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {records
                  .slice(recordsPage * RECORDS_PAGE_SIZE, (recordsPage + 1) * RECORDS_PAGE_SIZE)
                  .map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 text-slate-400 text-[11px]">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200">{r.input_filename}</td>
                    <td className="px-4 py-2.5 text-cyan-400">{r.model_version_tag}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] px-2 py-0.5 rounded border bg-emerald-950 text-emerald-400 border-emerald-800">
                        {r.verification_status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300">
                      {(r.highest_confidence * 100).toFixed(0)}%
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-400 text-[10px] select-all">
                      {(r.evidence_hash || r.output_hash).slice(0, 14)}...
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{r.executor_username}</td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => handleVerifyEvidence(r.id)}
                        className="px-2 py-1 text-[10px] font-mono rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
                      >
                        Verify 🔍
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Records Pagination Controls */}
        {Math.ceil(records.length / RECORDS_PAGE_SIZE) > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800/80 text-xs font-mono">
            <span className="text-slate-500">
              Showing {recordsPage * RECORDS_PAGE_SIZE + 1}–
              {Math.min((recordsPage + 1) * RECORDS_PAGE_SIZE, records.length)} of {records.length} records
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setRecordsPage((p) => Math.max(0, p - 1))}
                disabled={recordsPage === 0}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                ← Prev
              </button>
              <span className="text-slate-400 px-1">
                Page {recordsPage + 1} / {Math.ceil(records.length / RECORDS_PAGE_SIZE)}
              </span>
              <button
                type="button"
                onClick={() =>
                  setRecordsPage((p) =>
                    Math.min(Math.ceil(records.length / RECORDS_PAGE_SIZE) - 1, p + 1)
                  )
                }
                disabled={recordsPage >= Math.ceil(records.length / RECORDS_PAGE_SIZE) - 1}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 5-Pillar Verification Modal Drawer */}
      {verificationModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-mono">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <span className="text-xl">🔍</span>
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  Cryptographic Evidence Verification
                </h3>
              </div>
              <button
                onClick={() => setVerificationModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5">
              {verifyingLoading ? (
                <div className="py-12 flex flex-col items-center justify-center space-y-3">
                  <LoadingSpinner size="lg" />
                  <p className="text-xs text-slate-400">
                    Executing 5-point cryptographic verification pipeline...
                  </p>
                </div>
              ) : verificationData ? (
                <>
                  {/* Overall Status Banner */}
                  <div
                    className={`p-4 rounded-xl border flex items-center justify-between ${
                      verificationData.overall_status === 'VERIFIED'
                        ? 'bg-emerald-950/50 border-emerald-800/80 text-emerald-300'
                        : verificationData.overall_status === 'TAMPERED'
                        ? 'bg-red-950/50 border-red-800/80 text-red-300'
                        : 'bg-amber-950/50 border-amber-800/80 text-amber-300'
                    }`}
                  >
                    <div>
                      <span className="text-xs uppercase tracking-wider block font-bold">
                        Verification Determination:
                      </span>
                      <p className="text-xl font-bold mt-0.5">
                        {verificationData.overall_status === 'VERIFIED'
                          ? '✅ VERIFIED — CRYPTOGRAPHIC INTEGRITY INTACT'
                          : verificationData.overall_status === 'TAMPERED'
                          ? '🚨 TAMPERED — INTEGRITY COMPROMISED'
                          : '⚠️ NOT VERIFIED — VALIDATION FAILED'}
                      </p>
                    </div>
                    <span className="text-xs px-2.5 py-1 rounded bg-slate-950/60 border border-current font-bold">
                      {verificationData.overall_status}
                    </span>
                  </div>

                  {/* 5-Pillar Verification Grid */}
                  <div className="space-y-2.5">
                    <p className="text-xs uppercase text-slate-400 tracking-wider font-bold">
                      5-Point Verification Breakdown:
                    </p>

                    <div className="grid grid-cols-1 gap-2 text-xs">
                      {/* 1. Input Integrity */}
                      <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span>{verificationData.input_integrity ? '🟢' : '🔴'}</span>
                          <div>
                            <span className="font-bold text-slate-200">1. Input Image Digest Match</span>
                            <p className="text-[11px] text-slate-400">Physical image on disk matches recorded SHA-256</p>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verificationData.input_integrity ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {verificationData.input_integrity ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>

                      {/* 2. Model Integrity */}
                      <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span>{verificationData.model_integrity ? '🟢' : '🔴'}</span>
                          <div>
                            <span className="font-bold text-slate-200">2. Model Weights Digest Match</span>
                            <p className="text-[11px] text-slate-400">Physical weights file matches approved version SHA-256</p>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verificationData.model_integrity ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {verificationData.model_integrity ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>

                      {/* 3. Provenance Valid */}
                      <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span>{verificationData.provenance_valid ? '🟢' : '🔴'}</span>
                          <div>
                            <span className="font-bold text-slate-200">3. Provenance & Authorization</span>
                            <p className="text-[11px] text-slate-400">Model version approved by reviewer & executor registered</p>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verificationData.provenance_valid ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {verificationData.provenance_valid ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>

                      {/* 4. Canonical Evidence Integrity */}
                      <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span>{verificationData.evidence_integrity ? '🟢' : '🔴'}</span>
                          <div>
                            <span className="font-bold text-slate-200">4. Canonical Evidence Integrity</span>
                            <p className="text-[11px] text-slate-400">Recomputed canonical evidence hash matches recorded hash</p>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verificationData.evidence_integrity ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {verificationData.evidence_integrity ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>

                      {/* 5. Signature Valid */}
                      <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span>{verificationData.signature_valid ? '🟢' : '🔴'}</span>
                          <div>
                            <span className="font-bold text-slate-200">5. Ed25519 Cryptographic Signature</span>
                            <p className="text-[11px] text-slate-400">Asymmetric signature verifies with system public key</p>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          verificationData.signature_valid ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {verificationData.signature_valid ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Discrepancies if any */}
                  {verificationData.discrepancies && verificationData.discrepancies.length > 0 && (
                    <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg space-y-1 text-xs">
                      <span className="font-bold text-red-400 block">Detected Integrity Discrepancies:</span>
                      <ul className="list-disc list-inside text-red-300 space-y-0.5 text-[11px]">
                        {verificationData.discrepancies.map((d, i) => (
                          <li key={i}>{d}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Evidence Technical Reference */}
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[10px] text-slate-400 space-y-1">
                    <div>
                      <span className="text-slate-500">CANONICAL EVIDENCE HASH: </span>
                      <span className="text-slate-200 select-all break-all">{verificationData.evidence_hash}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">VERIFICATION TIMESTAMP: </span>
                      <span className="text-slate-300">{new Date(verificationData.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </>
              ) : null}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 bg-slate-950/80 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setVerificationModalOpen(false)}
                className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors border border-slate-700"
              >
                Close Verification Panel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}