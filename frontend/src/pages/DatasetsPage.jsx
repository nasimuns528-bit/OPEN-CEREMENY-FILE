import React, { useEffect, useState } from 'react'
import api from '../api/axios'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

export default function DatasetsPage() {
  const { user, isDataContributor, isAdmin, isReviewer } = useAuth()
  const canUpload = isDataContributor || isAdmin

  const [datasets, setDatasets] = useState([])
  const [selectedDataset, setSelectedDataset] = useState(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newDatasetName, setNewDatasetName] = useState('')
  const [newDatasetDesc, setNewDatasetDesc] = useState('')
  const [uploadingFiles, setUploadingFiles] = useState(false)
  const [freezingVersion, setFreezingVersion] = useState(false)
  const [versionTagInput, setVersionTagInput] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  const fetchDatasets = async () => {
    try {
      setLoading(true)
      const { data } = await api.get('/datasets')
      setDatasets(data)
      if (data.length > 0 && !selectedDataset) {
        fetchDatasetDetail(data[0].id)
      }
    } catch (err) {
      setErrorMsg('Failed to load datasets.')
    } finally {
      setLoading(false)
    }
  }

  const fetchDatasetDetail = async (id) => {
    try {
      const { data } = await api.get(`/datasets/${id}`)
      setSelectedDataset(data)
      setVerifyResult(null)
    } catch (err) {
      setErrorMsg('Failed to load dataset details.')
    }
  }

  useEffect(() => {
    fetchDatasets()
  }, [])

  const handleCreateDataset = async (e) => {
    e.preventDefault()
    setErrorMsg('')
    try {
      const { data } = await api.post('/datasets', {
        name: newDatasetName,
        description: newDatasetDesc,
      })
      setShowCreateModal(false)
      setNewDatasetName('')
      setNewDatasetDesc('')
      setSuccessMsg(`Dataset "${data.name}" created successfully.`)
      await fetchDatasets()
      fetchDatasetDetail(data.id)
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Failed to create dataset.')
    }
  }

  const handleFileUpload = async (e) => {
    const files = e.target.files
    if (!files || files.length === 0 || !selectedDataset) return

    setErrorMsg('')
    setSuccessMsg('')
    setUploadingFiles(true)

    const formData = new FormData()
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i])
    }

    try {
      await api.post(`/datasets/${selectedDataset.id}/files`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setSuccessMsg(`Successfully uploaded ${files.length} file(s).`)
      fetchDatasetDetail(selectedDataset.id)
      fetchDatasets()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'File upload failed.')
    } finally {
      setUploadingFiles(false)
      e.target.value = null
    }
  }

  const handleFreezeVersion = async () => {
    if (!selectedDataset) return
    setFreezingVersion(true)
    setErrorMsg('')
    try {
      const payload = versionTagInput.trim() ? { version_tag: versionTagInput.trim() } : {}
      const { data } = await api.post(`/datasets/${selectedDataset.id}/versions`, payload)
      setSuccessMsg(`Version ${data.version_tag} frozen with hash: ${data.dataset_hash.slice(0, 12)}...`)
      setVersionTagInput('')
      fetchDatasetDetail(selectedDataset.id)
      fetchDatasets()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Failed to freeze version.')
    } finally {
      setFreezingVersion(false)
    }
  }

  const handleVerifyIntegrity = async () => {
    if (!selectedDataset) return
    setVerifying(true)
    setErrorMsg('')
    try {
      const { data } = await api.post(`/datasets/${selectedDataset.id}/verify`)
      setVerifyResult(data)
      fetchDatasetDetail(selectedDataset.id)
      fetchDatasets()
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Integrity verification failed.')
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
            <span>📁</span> DATASET INTEGRITY & PROVENANCE
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Zero-trust multi-file cryptographic tracking · SHA-256 composite digests
          </p>
        </div>
        {canUpload && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs transition-colors shadow-[0_0_15px_rgba(16,185,129,0.25)] flex items-center gap-2"
          >
            <span>+</span> NEW DATASET
          </button>
        )}
      </div>

      {/* Notification banners */}
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

      {/* Main Grid: Dataset List vs Details */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Col: Dataset List */}
        <div className="lg:col-span-4 space-y-3">
          <div className="text-xs font-mono text-slate-400 uppercase tracking-wider px-1">
            Registered Datasets ({datasets.length})
          </div>

          {loading ? (
            <div className="flex justify-center p-8"><LoadingSpinner /></div>
          ) : datasets.length === 0 ? (
            <div className="p-6 text-center border border-slate-800/80 rounded-xl bg-slate-900/30 text-slate-500 text-xs font-mono">
              No datasets registered yet.
            </div>
          ) : (
            <div className="space-y-2">
              {datasets.map((ds) => {
                const isSelected = selectedDataset?.id === ds.id
                const isTampered = ds.status === 'TAMPERED'
                const isVerified = ds.status === 'VERIFIED'

                return (
                  <div
                    key={ds.id}
                    onClick={() => fetchDatasetDetail(ds.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-slate-900 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.1)]'
                        : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-sm text-slate-200 truncate">{ds.name}</span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          isTampered
                            ? 'bg-red-950 text-red-400 border-red-700'
                            : isVerified
                            ? 'bg-cyan-950 text-cyan-400 border-cyan-700'
                            : 'bg-emerald-950 text-emerald-400 border-emerald-700'
                        }`}
                      >
                        {ds.status}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-2">
                      <span>Owner: {ds.owner_username}</span>
                      <span>{ds.file_count} files</span>
                    </div>
                    {ds.current_hash && (
                      <div className="text-[10px] font-mono text-slate-500 mt-1 truncate">
                        Hash: {ds.current_hash.slice(0, 16)}...
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right Col: Selected Dataset Detail View */}
        <div className="lg:col-span-8">
          {selectedDataset ? (
            <div className="space-y-5">
              {/* Dataset Info Card */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <h2 className="text-xl font-bold font-mono text-slate-100">{selectedDataset.name}</h2>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      {selectedDataset.description || 'No description provided.'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleVerifyIntegrity}
                      disabled={verifying}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono transition-colors flex items-center gap-2"
                    >
                      {verifying ? <LoadingSpinner size="sm" /> : '🛡️ VERIFY INTEGRITY'}
                    </button>
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">INTEGRITY STATUS</span>
                    <span
                      className={`font-bold ${
                        selectedDataset.status === 'TAMPERED'
                          ? 'text-red-400'
                          : selectedDataset.status === 'VERIFIED'
                          ? 'text-cyan-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {selectedDataset.status}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">ACTIVE VERSION</span>
                    <span className="text-slate-200 font-bold">{selectedDataset.current_version || 'v1.0 (Draft)'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">TOTAL FILES</span>
                    <span className="text-slate-200">{selectedDataset.files?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">CONTRIBUTOR</span>
                    <span className="text-slate-200">{selectedDataset.owner_username}</span>
                  </div>
                </div>

                {/* Composite Hash Display */}
                {selectedDataset.current_hash && (
                  <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
                    <div className="text-[10px] font-mono text-slate-500 mb-1">
                      DETERMINISTIC COMPOSITE DATASET HASH (SHA-256):
                    </div>
                    <div className="text-xs font-mono text-emerald-400 select-all break-all">
                      {selectedDataset.current_hash}
                    </div>
                  </div>
                )}
              </div>

              {/* Tamper Warning Banner if verification failed */}
              {verifyResult && verifyResult.status === 'TAMPERED' && (
                <div className="p-4 bg-red-950/40 border border-red-600/80 rounded-xl space-y-2 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
                  <div className="flex items-center gap-2 text-red-400 font-mono font-bold text-sm">
                    <span>⚠️</span> TAMPER DETECTION TRIGGERED!
                  </div>
                  <p className="text-xs text-red-300 font-mono">
                    {verifyResult.message} Discrepancies detected between recorded digests and disk byte streams.
                  </p>
                  <div className="space-y-1 pt-2">
                    {verifyResult.file_results
                      .filter((r) => r.status !== 'VERIFIED')
                      .map((r) => (
                        <div key={r.file_id} className="text-[11px] font-mono bg-black/40 p-2 rounded border border-red-800/50 text-red-300">
                          <div><strong>File:</strong> {r.filename} ({r.status})</div>
                          <div>Expected: <span className="text-slate-400">{r.expected_hash}</span></div>
                          <div>Actual:   <span className="text-red-400">{r.current_hash || 'FILE_MISSING'}</span></div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Verification Success Banner */}
              {verifyResult && verifyResult.status === 'VERIFIED' && (
                <div className="p-4 bg-cyan-950/40 border border-cyan-500/60 rounded-xl space-y-1">
                  <div className="flex items-center gap-2 text-cyan-400 font-mono font-bold text-sm">
                    <span>✅</span> INTEGRITY CONFIRMED
                  </div>
                  <p className="text-xs text-cyan-300 font-mono">
                    All {verifyResult.total_files_checked} physical files on disk matched their cryptographic hashes perfectly.
                  </p>
                </div>
              )}

              {/* Version Freezing & File Upload Controls */}
              {canUpload && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {/* Upload Card */}
                  <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 space-y-3">
                    <span className="text-xs font-mono font-bold text-slate-300 block">
                      UPLOAD DATASET FILES / ZIP
                    </span>
                    <label className="block w-full cursor-pointer p-4 border border-dashed border-slate-700 hover:border-emerald-500/50 rounded-lg text-center transition-colors bg-slate-950/50">
                      <span className="text-xs font-mono text-slate-400 block">
                        {uploadingFiles ? 'UPLOADING...' : 'Drop images or ZIP archive here'}
                      </span>
                      <span className="text-[10px] font-mono text-slate-600 block mt-1">
                        PNG, JPG, TIFF, CSV, JSON, ZIP
                      </span>
                      <input
                        type="file"
                        multiple
                        disabled={uploadingFiles}
                        onChange={handleFileUpload}
                        className="hidden"
                      />
                    </label>
                  </div>

                  {/* Freeze Version Card */}
                  <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 space-y-3">
                    <span className="text-xs font-mono font-bold text-slate-300 block">
                      FREEZE DATASET VERSION
                    </span>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder="e.g. v1.1 (optional)"
                        value={versionTagInput}
                        onChange={(e) => setVersionTagInput(e.target.value)}
                        className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                      />
                      <button
                        onClick={handleFreezeVersion}
                        disabled={freezingVersion}
                        className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-mono font-bold transition-colors"
                      >
                        {freezingVersion ? <LoadingSpinner size="sm" /> : 'FREEZE'}
                      </button>
                    </div>
                    <p className="text-[10px] font-mono text-slate-500">
                      Computes composite hash across all current files and immutably links them to this version.
                    </p>
                  </div>
                </div>
              )}

              {/* Files Table */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                    Files In Dataset ({selectedDataset.files?.length || 0})
                  </span>
                </div>
                {selectedDataset.files?.length === 0 ? (
                  <div className="p-6 text-center text-xs font-mono text-slate-500">
                    No files uploaded yet.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                        <tr>
                          <th className="px-4 py-2.5">Filename</th>
                          <th className="px-4 py-2.5">SHA-256 Hash</th>
                          <th className="px-4 py-2.5">Size</th>
                          <th className="px-4 py-2.5">Uploader</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {selectedDataset.files.map((file) => (
                          <tr key={file.id} className="hover:bg-slate-800/30">
                            <td className="px-4 py-2.5 text-slate-200 font-medium">{file.original_filename}</td>
                            <td className="px-4 py-2.5 text-emerald-400/90 select-all font-mono text-[11px]">
                              {file.sha256_hash.slice(0, 16)}...{file.sha256_hash.slice(-8)}
                            </td>
                            <td className="px-4 py-2.5 text-slate-400">
                              {(file.file_size / 1024).toFixed(1)} KB
                            </td>
                            <td className="px-4 py-2.5 text-slate-400">{file.uploaded_by_username}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Version History Table */}
              {selectedDataset.versions?.length > 0 && (
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800">
                    <span className="text-xs font-mono font-bold text-slate-300 uppercase">
                      Frozen Version History ({selectedDataset.versions.length})
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                        <tr>
                          <th className="px-4 py-2.5">Version</th>
                          <th className="px-4 py-2.5">Composite Hash</th>
                          <th className="px-4 py-2.5">Files</th>
                          <th className="px-4 py-2.5">Total Size</th>
                          <th className="px-4 py-2.5">Frozen By</th>
                          <th className="px-4 py-2.5">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {selectedDataset.versions.map((ver) => (
                          <tr key={ver.id} className="hover:bg-slate-800/30">
                            <td className="px-4 py-2.5 text-emerald-400 font-bold">{ver.version_tag}</td>
                            <td className="px-4 py-2.5 text-slate-300 select-all text-[11px]">
                              {ver.dataset_hash.slice(0, 16)}...
                            </td>
                            <td className="px-4 py-2.5 text-slate-400">{ver.file_count}</td>
                            <td className="px-4 py-2.5 text-slate-400">
                              {(ver.total_size / 1024).toFixed(1)} KB
                            </td>
                            <td className="px-4 py-2.5 text-slate-400">{ver.created_by_username}</td>
                            <td className="px-4 py-2.5 text-slate-500 text-[10px]">
                              {new Date(ver.created_at).toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center border border-slate-800 rounded-xl bg-slate-900/20 text-slate-500 font-mono text-xs">
              Select a dataset from the list to inspect integrity and provenance.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create Dataset */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold font-mono text-slate-100">REGISTER NEW CV DATASET</h3>
            <form onSubmit={handleCreateDataset} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">DATASET NAME</label>
                <input
                  type="text"
                  required
                  value={newDatasetName}
                  onChange={(e) => setNewDatasetName(e.target.value)}
                  placeholder="e.g. YOLOv8 Traffic Surveillance"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">DESCRIPTION</label>
                <textarea
                  value={newDatasetDesc}
                  onChange={(e) => setNewDatasetDesc(e.target.value)}
                  placeholder="Provide scope, camera specs, labeling taxonomy..."
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
    </div>
  )
}
