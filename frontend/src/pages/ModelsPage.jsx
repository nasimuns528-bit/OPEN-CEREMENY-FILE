import React, { useEffect, useState } from 'react'
import api from '../api/axios'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

export default function ModelsPage() {
  const { user, isModelContributor, isReviewer, isAdmin } = useAuth()
  const canUpload = isModelContributor || isAdmin
  const canApprove = isReviewer || isAdmin

  const [models, setModels] = useState([])
  const [selectedModel, setSelectedModel] = useState(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [selectedScanFindings, setSelectedScanFindings] = useState(null)

  // Form states
  const [newModelName, setNewModelName] = useState('')
  const [newModelDesc, setNewModelDesc] = useState('')
  const [newModelFramework, setNewModelFramework] = useState('YOLOv8')
  const [newModelType, setNewModelType] = useState('object_detection')

  const [versionTag, setVersionTag] = useState('v1.0')
  const [datasetVersionRef, setDatasetVersionRef] = useState('')
  const [uploadFile, setUploadFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [approving, setApproving] = useState(false)

  const [errorMsg, setErrorMsg] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  const fetchModels = async () => {
    try {
      setLoading(true)
      const { data } = await api.get('/models')
      setModels(data)
      if (data.length > 0 && !selectedModel) {
        fetchModelDetail(data[0].id)
      }
    } catch (err) {
      setErrorMsg('Failed to load model registry.')
    } finally {
      setLoading(false)
    }
  }

  const fetchModelDetail = async (id) => {
    try {
      const { data } = await api.get(`/models/${id}`)
      setSelectedModel(data)
      setVerifyResult(null)
    } catch (err) {
      setErrorMsg('Failed to load model details.')
    }
  }

  useEffect(() => {
    fetchModels()
  }, [])

  const handleCreateModel = async (e) => {
    e.preventDefault()
    setErrorMsg('')
    try {
      const { data } = await api.post('/models', {
        name: newModelName,
        description: newModelDesc,
        framework: newModelFramework,
        model_type: newModelType,
      })
      setShowCreateModal(false)
      setNewModelName('')
      setNewModelDesc('')
      setSuccessMsg(`Model "${data.name}" created successfully.`)
      await fetchModels()
      fetchModelDetail(data.id)
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Failed to create model.')
    }
  }

  const handleUploadVersion = async (e) => {
    e.preventDefault()
    if (!uploadFile || !selectedModel) return

    setUploading(true)
    setErrorMsg('')
    setSuccessMsg('')

    const formData = new FormData()
    formData.append('version_tag', versionTag)
    if (datasetVersionRef) {
      formData.append('associated_dataset_version', datasetVersionRef)
    }
    formData.append('file', uploadFile)

    try {
      const { data } = await api.post(`/models/${selectedModel.id}/versions`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setShowUploadModal(false)
      setUploadFile(null)
      setSuccessMsg(`Version ${data.version_tag} uploaded! Static scan result: ${data.security_scan_status}`)
      fetchModelDetail(selectedModel.id)
      fetchModels()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Failed to upload model weights.')
    } finally {
      setUploading(false)
    }
  }

  const handleApproveVersion = async (versionId) => {
    if (!selectedModel) return
    setApproving(true)
    setErrorMsg('')
    try {
      const { data } = await api.post(`/models/${selectedModel.id}/versions/${versionId}/approve`)
      setSuccessMsg(`Version ${data.version_tag} APPROVED and cryptographically signed with Ed25519!`)
      fetchModelDetail(selectedModel.id)
      fetchModels()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Approval failed.')
    } finally {
      setApproving(false)
    }
  }

  const handleVerifyVersion = async (versionId) => {
    if (!selectedModel) return
    setVerifying(true)
    setErrorMsg('')
    try {
      const { data } = await api.post(`/models/${selectedModel.id}/versions/${versionId}/verify`)
      setVerifyResult(data)
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Model verification failed.')
    } finally {
      setVerifying(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold font-mono tracking-wider text-slate-100 flex items-center gap-2">
            <span>🧠</span> COMPUTER VISION MODEL REGISTRY
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Static bytecode vulnerability scanning · Ed25519 cryptographic signing · 5-point eligibility verification
          </p>
        </div>
        {canUpload && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs transition-colors shadow-[0_0_15px_rgba(16,185,129,0.25)] flex items-center gap-2"
          >
            <span>+</span> REGISTER MODEL
          </button>
        )}
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 text-xs font-mono">
          [ERROR] {errorMsg}
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800/80 rounded-lg text-emerald-300 text-xs font-mono">
          [SUCCESS] {successMsg}
        </div>
      )}

      {/* Main Grid: Catalog vs Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Col: Model List */}
        <div className="lg:col-span-4 space-y-3">
          <div className="text-xs font-mono text-slate-400 uppercase tracking-wider px-1">
            Registered Models ({models.length})
          </div>

          {loading ? (
            <div className="flex justify-center p-8"><LoadingSpinner /></div>
          ) : models.length === 0 ? (
            <div className="p-6 text-center border border-slate-800/80 rounded-xl bg-slate-900/30 text-slate-500 text-xs font-mono">
              No models registered yet.
            </div>
          ) : (
            <div className="space-y-2">
              {models.map((m) => {
                const isSelected = selectedModel?.id === m.id
                return (
                  <div
                    key={m.id}
                    onClick={() => fetchModelDetail(m.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-slate-900 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.1)]'
                        : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-sm text-slate-200 truncate">{m.name}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-blue-950 text-blue-400 border-blue-800">
                        {m.framework}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-2">
                      <span>Owner: {m.owner_username}</span>
                      <span className={m.latest_approval === 'APPROVED' ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                        {m.latest_approval || 'NO VERSIONS'}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right Col: Selected Model Detail & Versions */}
        <div className="lg:col-span-8">
          {selectedModel ? (
            <div className="space-y-5">
              {/* Model Header Card */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <h2 className="text-xl font-bold font-mono text-slate-100">{selectedModel.name}</h2>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      {selectedModel.description || 'No description provided.'}
                    </p>
                  </div>
                  {canUpload && (
                    <button
                      onClick={() => setShowUploadModal(true)}
                      className="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono transition-colors"
                    >
                      + UPLOAD VERSION
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">FRAMEWORK</span>
                    <span className="text-slate-200 font-bold">{selectedModel.framework}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">TASK TYPE</span>
                    <span className="text-slate-200">{selectedModel.model_type}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">REGISTERED BY</span>
                    <span className="text-slate-200">{selectedModel.owner_username}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">VERSIONS COUNT</span>
                    <span className="text-slate-200">{selectedModel.versions?.length || 0}</span>
                  </div>
                </div>
              </div>

              {/* Verification Result Banner */}
              {verifyResult && (
                <div
                  className={`p-4 rounded-xl border text-xs font-mono space-y-2 ${
                    verifyResult.deployment_eligible
                      ? 'bg-emerald-950/40 border-emerald-500/60 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.15)]'
                      : 'bg-red-950/40 border-red-500/80 text-red-300 shadow-[0_0_20px_rgba(239,68,68,0.2)]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm">
                      {verifyResult.deployment_eligible ? '✅ MODEL INTEGRITY VERIFIED — INFERENCE ELIGIBLE' : '⚠️ MODEL BLOCKED FROM INFERENCE'}
                    </span>
                    <span className="px-2 py-0.5 rounded border border-current text-[10px]">
                      {verifyResult.version_tag}
                    </span>
                  </div>
                  <p>{verifyResult.message}</p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-current/30 text-[11px]">
                    <div>Disk Hash Match: <span className="font-bold">{verifyResult.file_hash_match ? 'PASS' : 'FAIL'}</span></div>
                    <div>Scan Status: <span className="font-bold">{verifyResult.scan_status}</span></div>
                    <div>Approval: <span className="font-bold">{verifyResult.approval_status}</span></div>
                    <div>Ed25519 Sig: <span className="font-bold">{verifyResult.signature_valid ? 'VALID' : 'INVALID'}</span></div>
                  </div>
                </div>
              )}

              {/* Versions List */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                    Model Versions ({selectedModel.versions?.length || 0})
                  </span>
                </div>
                {selectedModel.versions?.length === 0 ? (
                  <div className="p-8 text-center text-xs font-mono text-slate-500">
                    No versions uploaded yet. Click "+ UPLOAD VERSION" to add weights.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-800/60">
                    {selectedModel.versions.map((ver) => (
                      <div key={ver.id} className="p-4 space-y-3 hover:bg-slate-800/20">
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                          <div className="flex items-center gap-3">
                            <span className="font-mono font-bold text-sm text-emerald-400">{ver.version_tag}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-slate-950 text-slate-400 border-slate-700">
                              {ver.model_format}
                            </span>
                            {ver.associated_dataset_version && (
                              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                                📁 Dataset: {ver.associated_dataset_version}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            {/* Security Scan Pill */}
                            <button
                              onClick={() => setSelectedScanFindings(ver.scans?.[0] || null)}
                              className={`text-[10px] font-mono px-2 py-0.5 rounded border cursor-pointer hover:opacity-80 ${
                                ver.security_scan_status === 'PASSED'
                                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                                  : ver.security_scan_status === 'FLAGGED'
                                  ? 'bg-red-950 text-red-400 border-red-800'
                                  : 'bg-amber-950 text-amber-400 border-amber-800'
                              }`}
                            >
                              Scan: {ver.security_scan_status} 🔍
                            </button>

                            {/* Approval Status Pill */}
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                                ver.approval_status === 'APPROVED'
                                  ? 'bg-cyan-950 text-cyan-400 border-cyan-800 font-bold'
                                  : 'bg-slate-950 text-slate-400 border-slate-700'
                              }`}
                            >
                              {ver.approval_status}
                            </span>
                          </div>
                        </div>

                        {/* Hash & Signature Info */}
                        <div className="p-2.5 bg-slate-950 border border-slate-800/80 rounded-lg text-[11px] font-mono space-y-1">
                          <div className="text-slate-400 truncate">
                            SHA-256: <span className="text-slate-200 select-all">{ver.sha256_hash}</span>
                          </div>
                          {ver.ed25519_signature && (
                            <div className="text-cyan-400 truncate">
                              Ed25519 Signature:{' '}
                              <span className="text-cyan-300/80 select-all font-bold">
                                {ver.ed25519_signature.slice(0, 32)}...
                              </span>
                            </div>
                          )}
                        </div>

                        {/* Actions Toolbar */}
                        <div className="flex items-center justify-between pt-1">
                          <div className="text-[10px] font-mono text-slate-500">
                            Uploaded by {ver.contributor_username} on {new Date(ver.created_at).toLocaleDateString()}
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleVerifyVersion(ver.id)}
                              disabled={verifying}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors"
                            >
                              {verifying ? 'Checking...' : 'Verify Integrity'}
                            </button>

                            {canApprove && ver.approval_status !== 'APPROVED' && (
                              <button
                                onClick={() => handleApproveVersion(ver.id)}
                                disabled={approving || ver.security_scan_status !== 'PASSED'}
                                className={`px-3 py-1 rounded text-xs font-mono font-bold transition-colors ${
                                  ver.security_scan_status === 'PASSED'
                                    ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                                    : 'bg-slate-800 text-slate-600 cursor-not-allowed border border-slate-700'
                                }`}
                              >
                                {approving ? 'Signing...' : 'Approve & Sign (Ed25519)'}
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center border border-slate-800 rounded-xl bg-slate-900/20 text-slate-500 font-mono text-xs">
              Select a model from the registry to inspect security scans and approvals.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create Model */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold font-mono text-slate-100">REGISTER NEW CV MODEL</h3>
            <form onSubmit={handleCreateModel} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">MODEL NAME</label>
                <input
                  type="text"
                  required
                  value={newModelName}
                  onChange={(e) => setNewModelName(e.target.value)}
                  placeholder="e.g. YOLOv8 Urban Vehicle Detector"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">FRAMEWORK</label>
                  <select
                    value={newModelFramework}
                    onChange={(e) => setNewModelFramework(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  >
                    <option value="YOLOv8">YOLOv8</option>
                    <option value="PyTorch">PyTorch</option>
                    <option value="ONNX">ONNX</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">TASK TYPE</label>
                  <input
                    type="text"
                    value={newModelType}
                    onChange={(e) => setNewModelType(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">DESCRIPTION</label>
                <textarea
                  value={newModelDesc}
                  onChange={(e) => setNewModelDesc(e.target.value)}
                  placeholder="Architecture details, training hyperparameters..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs transition-colors"
                >
                  REGISTER
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Upload Model Version */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold font-mono text-slate-100">
              UPLOAD WEIGHTS — {selectedModel?.name}
            </h3>
            <form onSubmit={handleUploadVersion} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">VERSION TAG</label>
                <input
                  type="text"
                  required
                  value={versionTag}
                  onChange={(e) => setVersionTag(e.target.value)}
                  placeholder="e.g. v1.0"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  ASSOCIATED DATASET VERSION (OPTIONAL)
                </label>
                <input
                  type="text"
                  value={datasetVersionRef}
                  onChange={(e) => setDatasetVersionRef(e.target.value)}
                  placeholder="e.g. traffic-v1.0"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">MODEL WEIGHTS FILE</label>
                <input
                  type="file"
                  required
                  accept=".pt,.onnx,.bin,.weights,.safetensors"
                  onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs font-mono text-slate-400 focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[10px] font-mono text-slate-500 block mt-1">
                  Supported formats: .pt, .onnx, .safetensors (Automated bytecode scan executed upon upload)
                </span>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={uploading || !uploadFile}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs transition-colors disabled:opacity-50"
                >
                  {uploading ? 'SCANNING & SAVING...' : 'UPLOAD & SCAN'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Security Scan Findings Inspector */}
      {selectedScanFindings && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                <span>🔍</span> STATIC SECURITY SCAN REPORT
              </h3>
              <button
                onClick={() => setSelectedScanFindings(null)}
                className="text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span>SCANNER: {selectedScanFindings.scanner_name}</span>
                <span className="font-bold text-emerald-400">{selectedScanFindings.scan_result}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] mb-1">ANALYSIS FINDINGS</span>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-[11px] overflow-x-auto max-h-64">
                  {selectedScanFindings.findings_json
                    ? JSON.stringify(JSON.parse(selectedScanFindings.findings_json), null, 2)
                    : 'Clean weights file — no malicious opcodes detected.'}
                </pre>
              </div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedScanFindings(null)}
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
