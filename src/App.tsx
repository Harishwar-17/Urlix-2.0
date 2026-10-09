import { useEffect, useState, useMemo, useRef } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  Activity,
  Server,
  Lock,
  Search,
  CheckCircle2,
  Clock,
  Layers,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Terminal,
  Info,
  XCircle,
  Copy,
  Check,
  BarChart3,
  Trash2,
  History as HistoryIcon,
  Download,
  Share2,
  Code2,
  QrCode,
  FileSpreadsheet,
  GitCompare,
  UploadCloud,
  EyeOff
} from 'lucide-react'
import {
  analyzeUrl,
  defangUrl,
  refangUrl,
  extractUrlsFromText,
  type AnalyzeResponse,
  type Finding
} from './engine/analyzer.ts'
import { decodeQrFromImageFile, getSampleQrTestDataUri } from './utils/qrScanner.ts'

interface HealthResponse {
  status: string
  service: string
  tagline: string
  version: string
  timestamp: string
  uptime_seconds: number
  environment: string
  detection_engine: string
}

type MainTab = 'inspector' | 'batch' | 'quishing' | 'defanger' | 'compare'

// Preset test scenarios for fast demo testing
const SAMPLE_TEST_CASES = [
  {
    label: 'Brand Spoofing & Subdomain Phish',
    url: 'http://login.microsoft.com.secure-auth-update.xyz/auth.php',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Misleading @ Authority Credential Trick',
    url: 'https://paypal.com@evil-phish.top/account-verify',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Direct IP Host with Login Path',
    url: 'http://192.168.1.100/login/update',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Punycode Homograph Domain',
    url: 'http://xn--pple-43d.com/store',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Open Redirect Attack',
    url: 'https://legit-service.com/login?redirect=https://evil-phish.top/harvest',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Public URL Shortener',
    url: 'https://bit.ly/3xSampleShortener',
    badge: 'Shortener',
    badgeColor: 'text-cyan-400 border-cyan-800 bg-cyan-950/40',
  },
  {
    label: 'Direct Executable Payload',
    url: 'https://bankofamerica-secure-login-update.com/patch/update-credentials.exe',
    badge: 'High Risk',
    badgeColor: 'text-rose-400 border-rose-800 bg-rose-950/40',
  },
  {
    label: 'Legitimate Web Service',
    url: 'https://github.com/explore',
    badge: 'Low Risk',
    badgeColor: 'text-emerald-400 border-emerald-800 bg-emerald-950/40',
  },
]

export default function App() {
  const [activeMainTab, setActiveMainTab] = useState<MainTab>('inspector')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true)
  const [pingLatency, setPingLatency] = useState<number | null>(null)

  // Single URL Analysis State
  const [inputUrl, setInputUrl] = useState<string>('')
  const [analyzing, setAnalyzing] = useState<boolean>(false)
  const [analysisResult, setAnalysisResult] = useState<AnalyzeResponse | null>(null)
  const [analysisError, setAnalysisError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({})
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false)
  const [copiedDefanged, setCopiedDefanged] = useState<boolean>(false)
  const [copiedJson, setCopiedJson] = useState<boolean>(false)
  const [activeDetailTab, setActiveDetailTab] = useState<'findings' | 'structure' | 'json' | 'ioc'>('findings')

  // History and Dashboard State
  const [history, setHistory] = useState<AnalyzeResponse[]>([])
  const [historyFilter, setHistoryFilter] = useState<'All' | 'High' | 'Medium' | 'Low'>('All')
  const [showClearConfirm, setShowClearConfirm] = useState<boolean>(false)

  // Batch & Email Scanner State
  const [rawBatchText, setRawBatchText] = useState<string>('')
  const [batchAnalyzing, setBatchAnalyzing] = useState<boolean>(false)
  const [batchResults, setBatchResults] = useState<AnalyzeResponse[]>([])
  const [copiedBatchCsv, setCopiedBatchCsv] = useState<boolean>(false)

  // Quishing (QR Scanner) State
  const [qrDecoding, setQrDecoding] = useState<boolean>(false)
  const [qrError, setQrError] = useState<string | null>(null)
  const [decodedQrUrl, setDecodedQrUrl] = useState<string | null>(null)
  const qrFileInputRef = useRef<HTMLInputElement | null>(null)

  // Defanger Tool State
  const [defangInput, setDefangInput] = useState<string>('https://login.microsoft.com.secure-auth-update.xyz/auth.php')
  const [defangMode, setDefangMode] = useState<'defang' | 'refang'>('defang')
  const [copiedDefangResult, setCopiedDefangResult] = useState<boolean>(false)

  // Clone Comparator State
  const [compareUrlA, setCompareUrlA] = useState<string>('https://login.microsoftonline.com')
  const [compareUrlB, setCompareUrlB] = useState<string>('http://login.microsoft.com.secure-auth-update.xyz/auth.php')
  const [comparisonResultA, setComparisonResultA] = useState<AnalyzeResponse | null>(null)
  const [comparisonResultB, setComparisonResultB] = useState<AnalyzeResponse | null>(null)

  // Load history on mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('urlix_history')
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory))
      } catch (e) {
        console.error('Failed to parse history', e)
      }
    }
  }, [])

  // Save history when it changes
  useEffect(() => {
    localStorage.setItem('urlix_history', JSON.stringify(history))
  }, [history])

  const fetchHealth = async () => {
    setLoadingHealth(true)
    const startTime = performance.now()
    try {
      const res = await fetch('/api/health')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: HealthResponse = await res.json()
      setPingLatency(Math.max(1, Math.round(performance.now() - startTime)))
      setHealth(data)
    } catch {
      setPingLatency(1)
      setHealth({
        status: 'healthy',
        service: 'URLIX Detection Engine',
        tagline: 'See the Link. Spot the Threat.',
        version: '0.3.0',
        timestamp: new Date().toISOString(),
        uptime_seconds: 1,
        environment: 'embedded',
        detection_engine: 'active_milestone_3',
      })
    } finally {
      setLoadingHealth(false)
    }
  }

  useEffect(() => {
    fetchHealth()
  }, [])

  const handleAnalyze = async (targetUrl?: string) => {
    const urlToTest = (targetUrl !== undefined ? targetUrl : inputUrl).trim()
    if (!urlToTest) {
      setAnalysisError('Please enter a URL to analyze.')
      setAnalysisResult(null)
      return
    }

    setAnalyzing(true)
    setAnalysisError(null)

    await new Promise((resolve) => setTimeout(resolve, 200))

    try {
      let data: AnalyzeResponse | null = null

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlToTest }),
        })

        const body = await res.json()

        if (!res.ok) {
          throw new Error(body.detail || body.error || `HTTP ${res.status}: Failed to analyze URL`)
        }
        data = body
      } catch (fetchErr: any) {
        if (
          fetchErr.message &&
          (fetchErr.message.includes('Scheme not supported') ||
            fetchErr.message.includes('Unsupported URL') ||
            fetchErr.message.includes('URL parameter') ||
            fetchErr.message.includes('Malformed URL') ||
            fetchErr.message.includes('Invalid scheme') ||
            fetchErr.message.includes('exceeds maximum permitted length'))
        ) {
          throw fetchErr
        }
        data = analyzeUrl(urlToTest)
      }

      if (!data) {
        throw new Error('Analysis yielded no result.')
      }

      setAnalysisResult(data)

      setHistory((prev) => {
        const newHistory = [data!, ...prev.filter((item) => item.submitted_url !== data!.submitted_url)].slice(0, 50)
        return newHistory
      })

      const initialExpanded: Record<string, boolean> = {}
      data.findings?.forEach((f: Finding) => {
        initialExpanded[f.rule_id] = true
      })
      setExpandedFindings(initialExpanded)
    } catch (err: any) {
      setAnalysisError(err.message || 'An unexpected error occurred during analysis.')
      setAnalysisResult(null)
    } finally {
      setAnalyzing(false)
    }
  }

  const toggleFinding = (ruleId: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [ruleId]: !prev[ruleId],
    }))
  }

  const copyUrl = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedUrl(true)
    setTimeout(() => setCopiedUrl(false), 2000)
  }

  const copyDefangedUrl = (text: string) => {
    navigator.clipboard.writeText(defangUrl(text))
    setCopiedDefanged(true)
    setTimeout(() => setCopiedDefanged(false), 2000)
  }

  const copyReportJson = () => {
    if (!analysisResult) return
    navigator.clipboard.writeText(JSON.stringify(analysisResult, null, 2))
    setCopiedJson(true)
    setTimeout(() => setCopiedJson(false), 2000)
  }

  const downloadReportJson = () => {
    if (!analysisResult) return
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `urlix-report-${analysisResult.hostname || 'scan'}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const confirmClearHistory = () => {
    setHistory([])
    setShowClearConfirm(false)
  }

  const stats = useMemo(() => {
    return {
      total: history.length,
      high: history.filter((s) => s.risk_category === 'High').length,
      medium: history.filter((s) => s.risk_category === 'Medium').length,
      low: history.filter((s) => s.risk_category === 'Low').length,
    }
  }, [history])

  const filteredHistory = useMemo(() => {
    if (historyFilter === 'All') return history
    return history.filter((s) => s.risk_category === historyFilter)
  }, [history, historyFilter])

  // Batch analysis handler
  const handleBatchAnalyze = async () => {
    const urls = extractUrlsFromText(rawBatchText)
    if (urls.length === 0) {
      alert('No valid URLs detected in the input text.')
      return
    }

    setBatchAnalyzing(true)
    await new Promise((r) => setTimeout(r, 250))

    try {
      const results: AnalyzeResponse[] = []
      for (const u of urls.slice(0, 30)) {
        try {
          results.push(analyzeUrl(u))
        } catch {
          // ignore invalid
        }
      }
      setBatchResults(results)
    } finally {
      setBatchAnalyzing(false)
    }
  }

  const exportBatchCsv = () => {
    if (batchResults.length === 0) return
    const headers = ['Submitted URL', 'Risk Category', 'Heuristic Score', 'Hostname', 'Findings Count', 'Threat Tags']
    const rows = batchResults.map((r) => [
      `"${r.submitted_url.replace(/"/g, '""')}"`,
      r.risk_category,
      r.heuristic_score,
      `"${r.hostname}"`,
      r.findings_count,
      `"${(r.threat_tags || []).join('; ')}"`,
    ])
    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `urlix-batch-scan-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
    setCopiedBatchCsv(true)
    setTimeout(() => setCopiedBatchCsv(false), 2000)
  }

  // Quishing handler
  const handleQrUpload = async (file: File) => {
    setQrDecoding(true)
    setQrError(null)
    setDecodedQrUrl(null)
    try {
      const decoded = await decodeQrFromImageFile(file)
      setDecodedQrUrl(decoded)
      // Automatically analyze the decoded link
      setInputUrl(decoded)
      setActiveMainTab('inspector')
      handleAnalyze(decoded)
    } catch (err: any) {
      setQrError(err.message || 'Failed to detect or parse QR code.')
    } finally {
      setQrDecoding(false)
    }
  }

  const handleTestQrSample = (type: 'phish' | 'legit') => {
    const url = getSampleQrTestDataUri(type)
    setDecodedQrUrl(url)
    setInputUrl(url)
    setActiveMainTab('inspector')
    handleAnalyze(url)
  }

  // Clone comparator handler
  const handleRunComparison = () => {
    try {
      if (compareUrlA) setComparisonResultA(analyzeUrl(compareUrlA))
      if (compareUrlB) setComparisonResultB(analyzeUrl(compareUrlB))
    } catch (e: any) {
      alert(`Comparison error: ${e.message}`)
    }
  }

  // Helper for risk badge styling
  const getRiskTheme = (category?: string) => {
    switch (category) {
      case 'High':
        return {
          badge: 'bg-rose-950/60 border-rose-600/70 text-rose-400',
          gradient: 'from-rose-500/20 via-rose-950/20 to-transparent',
          scoreBar: 'bg-gradient-to-r from-amber-500 via-rose-500 to-red-600',
          scoreText: 'text-rose-400',
          border: 'border-rose-900/60',
          icon: <ShieldAlert className="w-8 h-8 text-rose-500" />,
        }
      case 'Medium':
        return {
          badge: 'bg-amber-950/60 border-amber-600/70 text-amber-400',
          gradient: 'from-amber-500/20 via-amber-950/20 to-transparent',
          scoreBar: 'bg-gradient-to-r from-emerald-500 via-yellow-500 to-amber-500',
          scoreText: 'text-amber-400',
          border: 'border-amber-900/60',
          icon: <AlertTriangle className="w-8 h-8 text-amber-400" />,
        }
      default:
        return {
          badge: 'bg-emerald-950/60 border-emerald-600/70 text-emerald-400',
          gradient: 'from-emerald-500/20 via-emerald-950/20 to-transparent',
          scoreBar: 'bg-gradient-to-r from-teal-500 to-emerald-500',
          scoreText: 'text-emerald-400',
          border: 'border-emerald-900/60',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
        }
    }
  }

  const currentTheme = analysisResult ? getRiskTheme(analysisResult.risk_category) : null

  return (
    <div className="relative min-h-screen bg-[#07090e] text-slate-100 cyber-grid selection:bg-cyan-500/20 selection:text-cyan-300">
      <div className="absolute inset-0 cyber-glow pointer-events-none" />

      {/* Header / Navbar */}
      <header className="relative z-10 border-b border-slate-800/80 bg-[#0b0f19]/80 backdrop-blur-md sticky top-0">
        <div className="max-w-6xl mx-auto px-4 h-16 sm:h-18 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-cyan-500 via-teal-500 to-emerald-500 p-[1.5px] shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-[#0b0f19] rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent">
                  URLIX
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-400">
                  Engine v0.3.0
                </span>
              </div>
              <p className="text-xs text-slate-400 tracking-tight hidden sm:block">
                See the Link. Spot the Threat.
              </p>
            </div>
          </div>

          {/* Engine Status & Latency Badge */}
          <div className="flex items-center gap-3">
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium transition-all ${
                loadingHealth
                  ? 'bg-amber-950/30 border-amber-800/50 text-amber-300'
                  : health
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
              }`}
            >
              <span className="relative flex h-2 w-2">
                {health && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                )}
                <span
                  className={`relative inline-flex rounded-full h-2 w-2 ${
                    loadingHealth
                      ? 'bg-amber-400'
                      : health
                      ? 'bg-emerald-500'
                      : 'bg-rose-500'
                  }`}
                ></span>
              </span>
              <span>
                {loadingHealth
                  ? 'Connecting...'
                  : health
                  ? `Engine Online (${pingLatency ?? 0}ms)`
                  : 'Engine Offline'}
              </span>
            </div>

            <button
              onClick={fetchHealth}
              disabled={loadingHealth}
              title="Refresh engine status"
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingHealth ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Global Navigation Mode Switcher Tabs */}
        <div className="border-t border-slate-800/60 bg-[#080b13]/60 px-4">
          <div className="max-w-6xl mx-auto flex items-center gap-1 sm:gap-2 overflow-x-auto py-2 text-xs font-medium">
            <button
              onClick={() => setActiveMainTab('inspector')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer ${
                activeMainTab === 'inspector'
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Link Inspector</span>
            </button>

            <button
              onClick={() => setActiveMainTab('batch')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer ${
                activeMainTab === 'batch'
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Batch & Email Extractor</span>
            </button>

            <button
              onClick={() => setActiveMainTab('quishing')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer ${
                activeMainTab === 'quishing'
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>Quishing (QR Phish)</span>
            </button>

            <button
              onClick={() => setActiveMainTab('defanger')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer ${
                activeMainTab === 'defanger'
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <EyeOff className="w-3.5 h-3.5" />
              <span>SOC URL Defanger</span>
            </button>

            <button
              onClick={() => {
                setActiveMainTab('compare')
                if (!comparisonResultA) handleRunComparison()
              }}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer ${
                activeMainTab === 'compare'
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Clone Comparator</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="relative z-10 max-w-6xl mx-auto px-4 py-8 sm:py-10 flex flex-col gap-10">
        {/* ========================================================= */}
        {/* TAB 1: SINGLE LINK INSPECTOR (CORE DETECTION) */}
        {/* ========================================================= */}
        {activeMainTab === 'inspector' && (
          <>
            {/* Hero Section & Input */}
            <section className="text-center max-w-3xl mx-auto flex flex-col items-center gap-5">
              <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-cyan-500/30 bg-cyan-950/30 text-cyan-300 text-xs font-medium shadow-sm">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Passive Explainable Heuristic Detection Engine</span>
              </div>

              <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
                See the Link.{' '}
                <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent">
                  Spot the Threat.
                </span>
              </h1>

              <p className="text-sm sm:text-base text-slate-300 leading-relaxed max-w-2xl">
                Inspect untrusted links with zero execution risk. URLIX deconstructs lexical structure,
                detects brand impersonation, typosquatting, and calculates an explainable heuristic risk score.
              </p>

              {/* Interactive URL Input Form */}
              <div className="w-full mt-2">
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    handleAnalyze()
                  }}
                  className="relative flex flex-col sm:flex-row items-center gap-2 p-2 rounded-2xl bg-[#0f1422] border border-slate-800 focus-within:border-cyan-500/70 shadow-2xl shadow-cyan-950/30 transition-all"
                >
                  <div className="flex items-center gap-2.5 px-3 w-full sm:flex-1">
                    <Search className="w-5 h-5 text-slate-500 shrink-0" />
                    <input
                      type="text"
                      value={inputUrl}
                      onChange={(e) => setInputUrl(e.target.value)}
                      placeholder="Paste URL to inspect (e.g. https://paypal.com@verify-auth.top/login)"
                      className="w-full bg-transparent text-sm sm:text-base text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
                      disabled={analyzing}
                    />
                    {inputUrl && (
                      <button
                        type="button"
                        onClick={() => setInputUrl('')}
                        className="text-slate-500 hover:text-slate-300 p-1 cursor-pointer"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                  <button
                    type="submit"
                    disabled={analyzing}
                    className="w-full sm:w-auto px-7 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-400 hover:to-teal-400 text-slate-950 font-bold text-sm tracking-wide shadow-md shadow-cyan-500/25 transition disabled:opacity-60 flex items-center justify-center gap-2 cursor-pointer"
                  >
                    {analyzing ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-4 h-4 text-slate-950" />
                        <span>Analyze Link</span>
                      </>
                    )}
                  </button>
                </form>

                {/* Zero-Execution Safety Banner */}
                <div className="flex items-center justify-center gap-2 mt-3 text-xs text-slate-400">
                  <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>
                    <strong>Zero-Execution Guarantee:</strong> Submitted URLs are parsed statically and{' '}
                    <span className="text-slate-200 underline decoration-slate-600">never visited or opened</span>.
                  </span>
                </div>

                {/* Quick-Test Sample Pills */}
                <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs">
                  <span className="text-slate-500 mr-1 flex items-center gap-1">
                    <Terminal className="w-3.5 h-3.5" /> Sample Test Links:
                  </span>
                  {SAMPLE_TEST_CASES.map((tc, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => {
                        setInputUrl(tc.url)
                        handleAnalyze(tc.url)
                      }}
                      className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono transition hover:scale-105 active:scale-95 cursor-pointer ${tc.badgeColor}`}
                      title={tc.url}
                    >
                      {tc.label}
                    </button>
                  ))}
                </div>
              </div>
            </section>

            {/* Error Notification Alert */}
            {analysisError && (
              <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-200 text-sm flex items-start gap-3 shadow-lg max-w-3xl mx-auto w-full">
                <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h4 className="font-semibold text-rose-300">Invalid URL or Request Error</h4>
                  <p className="text-xs text-rose-200/90 mt-0.5">{analysisError}</p>
                </div>
              </div>
            )}

            {/* Loading Spinner Skeleton */}
            {analyzing && (
              <div className="max-w-3xl mx-auto w-full p-8 rounded-2xl bg-[#0c101c] border border-slate-800 flex flex-col items-center justify-center gap-3">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                <p className="text-sm font-semibold text-white">Running Explainable Heuristic Checks...</p>
                <p className="text-xs text-slate-400 text-center">
                  Inspecting scheme, entropy, punycode, brand lookalikes, authority delimiters, and file extensions
                </p>
              </div>
            )}

            {/* Security Dashboard */}
            {history.length > 0 && !analyzing && !analysisResult && (
              <section className="flex flex-col gap-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                      <BarChart3 className="w-5 h-5 text-cyan-400" />
                      Security Dashboard
                    </h2>
                    <p className="text-xs text-slate-400">Aggregated statistics from your recent scan history</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="p-5 rounded-2xl bg-[#0b0f19] border border-slate-800 shadow-xl flex flex-col items-center">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500">Total Scans</span>
                    <span className="text-3xl font-extrabold text-white mt-1">{stats.total}</span>
                  </div>
                  <div className="p-5 rounded-2xl bg-[#0b0f19] border border-rose-900/40 shadow-xl flex flex-col items-center">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-rose-500">High Risk</span>
                    <span className="text-3xl font-extrabold text-rose-400 mt-1">{stats.high}</span>
                  </div>
                  <div className="p-5 rounded-2xl bg-[#0b0f19] border border-amber-900/40 shadow-xl flex flex-col items-center">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-amber-500">Medium Risk</span>
                    <span className="text-3xl font-extrabold text-amber-400 mt-1">{stats.medium}</span>
                  </div>
                  <div className="p-5 rounded-2xl bg-[#0b0f19] border border-emerald-900/40 shadow-xl flex flex-col items-center">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-emerald-500">Low Risk</span>
                    <span className="text-3xl font-extrabold text-emerald-400 mt-1">{stats.low}</span>
                  </div>
                </div>

                {/* Visual Risk Distribution Bar */}
                <div className="w-full h-3 rounded-full bg-slate-800 flex overflow-hidden border border-slate-700/50">
                  <div 
                    className="h-full bg-rose-500 transition-all duration-500" 
                    style={{ width: `${(stats.high / (stats.total || 1)) * 100}%` }}
                    title={`High Risk: ${stats.high}`}
                  />
                  <div 
                    className="h-full bg-amber-500 transition-all duration-500" 
                    style={{ width: `${(stats.medium / (stats.total || 1)) * 100}%` }}
                    title={`Medium Risk: ${stats.medium}`}
                  />
                  <div 
                    className="h-full bg-emerald-500 transition-all duration-500" 
                    style={{ width: `${(stats.low / (stats.total || 1)) * 100}%` }}
                    title={`Low Risk: ${stats.low}`}
                  />
                </div>
              </section>
            )}

            {/* Scan History List */}
            {history.length > 0 && !analyzing && !analysisResult && (
              <section className="flex flex-col gap-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                      <HistoryIcon className="w-5 h-5 text-cyan-400" />
                      Scan History
                    </h2>
                    <p className="text-xs text-slate-400">Your latest 50 security inspections</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="flex rounded-lg border border-slate-800 bg-[#080b13] p-1 text-xs">
                      {(['All', 'High', 'Medium', 'Low'] as const).map((cat) => (
                        <button
                          key={cat}
                          onClick={() => setHistoryFilter(cat)}
                          className={`px-2.5 py-1 rounded-md text-xs font-medium transition cursor-pointer ${
                            historyFilter === cat
                              ? 'bg-slate-700 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {cat}
                        </button>
                      ))}
                    </div>

                    <button
                      onClick={() => setShowClearConfirm(true)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-900/40 bg-rose-950/20 text-rose-400 hover:bg-rose-950/40 transition text-xs font-semibold cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Clear
                    </button>
                  </div>
                </div>

                {/* Clear Confirmation Dialog in UI */}
                {showClearConfirm && (
                  <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 text-xs text-rose-200">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>Are you sure you want to permanently clear your scan history?</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setShowClearConfirm(false)}
                        className="px-3 py-1 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-medium cursor-pointer"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={confirmClearHistory}
                        className="px-3 py-1 rounded-lg bg-rose-600 text-white hover:bg-rose-500 text-xs font-bold cursor-pointer"
                      >
                        Yes, Clear
                      </button>
                    </div>
                  </div>
                )}

                <div className="overflow-hidden rounded-2xl border border-slate-800 bg-[#0b0f19] shadow-2xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="bg-slate-900/50 border-b border-slate-800">
                          <th className="px-6 py-4 font-bold text-slate-400 uppercase tracking-wider text-[10px]">URL / Target Host</th>
                          <th className="px-6 py-4 font-bold text-slate-400 uppercase tracking-wider text-[10px]">Category</th>
                          <th className="px-6 py-4 font-bold text-slate-400 uppercase tracking-wider text-[10px]">Heuristic Risk</th>
                          <th className="px-6 py-4 font-bold text-slate-400 uppercase tracking-wider text-[10px]">Timestamp</th>
                          <th className="px-6 py-4 font-bold text-slate-400 uppercase tracking-wider text-[10px] text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/50">
                        {filteredHistory.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-6 py-8 text-center text-slate-500 text-xs">
                              No scans found matching category &quot;{historyFilter}&quot;.
                            </td>
                          </tr>
                        ) : (
                          filteredHistory.map((scan, i) => {
                            const theme = getRiskTheme(scan.risk_category)
                            return (
                              <tr key={i} className="hover:bg-slate-800/30 transition group">
                                <td className="px-6 py-4">
                                  <div className="flex flex-col max-w-md">
                                    <span className="text-slate-200 font-mono text-xs truncate" title={scan.submitted_url}>
                                      {scan.submitted_url}
                                    </span>
                                    <span className="text-[10px] text-slate-500 mt-0.5 truncate font-mono">
                                      Host: {scan.hostname}
                                    </span>
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${theme.badge}`}>
                                    {scan.risk_category}
                                  </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <div className="flex items-center gap-2">
                                    <span className={`font-mono font-bold ${theme.scoreText}`}>{scan.heuristic_score}</span>
                                    <div className="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                                      <div className={`h-full ${theme.scoreBar}`} style={{ width: `${scan.heuristic_score}%` }} />
                                    </div>
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-xs text-slate-500">
                                  {new Date(scan.analyzed_at).toLocaleString()}
                                </td>
                                <td className="px-6 py-4 text-right whitespace-nowrap">
                                  <button
                                    onClick={() => {
                                      setAnalysisResult(scan)
                                      window.scrollTo({ top: 0, behavior: 'smooth' })
                                    }}
                                    className="text-cyan-400 hover:text-cyan-300 text-xs font-bold transition flex items-center justify-end gap-1 ml-auto cursor-pointer"
                                  >
                                    View Report <ArrowRight className="w-3 h-3" />
                                  </button>
                                </td>
                              </tr>
                            )
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>
            )}

            {/* Analysis Results Display */}
            {analysisResult && !analyzing && currentTheme && (
              <div className="flex flex-col gap-8">
                {/* Top Risk Score & Verdict Banner */}
                <section
                  className={`relative overflow-hidden rounded-2xl border p-6 sm:p-8 bg-[#0b0f19] ${currentTheme.border} shadow-2xl`}
                >
                  <div
                    className={`absolute inset-0 bg-gradient-to-r ${currentTheme.gradient} opacity-40 pointer-events-none`}
                  />

                  <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-slate-800/80">
                    <div className="flex items-start gap-4">
                      <div className="p-3 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-inner">
                        {currentTheme.icon}
                      </div>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-xs uppercase font-extrabold tracking-wider px-3 py-1 rounded-full border ${currentTheme.badge}`}
                          >
                            {analysisResult.risk_category} Risk Category
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            {analysisResult.findings_count} Observation
                            {analysisResult.findings_count === 1 ? '' : 's'}
                          </span>
                          {/* Threat tags pills */}
                          {analysisResult.threat_tags?.map((tag) => (
                            <span key={tag} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                              #{tag}
                            </span>
                          ))}
                        </div>
                        <h2 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
                          {analysisResult.score_description}
                        </h2>
                        <p className="text-xs sm:text-sm text-slate-300 mt-1 max-w-xl leading-relaxed">
                          {analysisResult.summary}
                        </p>
                      </div>
                    </div>

                    {/* Score Dial / Numerical Display */}
                    <div className="flex flex-col items-center justify-center p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80 min-w-[170px] text-center shrink-0">
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        Heuristic Score
                      </span>
                      <div className="flex items-baseline gap-1 my-1">
                        <span className={`text-4xl font-extrabold font-mono ${currentTheme.scoreText}`}>
                          {analysisResult.heuristic_score}
                        </span>
                        <span className="text-slate-500 font-bold text-sm">/100</span>
                      </div>
                      {/* Visual Progress bar */}
                      <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden mt-1">
                        <div
                          className={`h-full ${currentTheme.scoreBar} transition-all duration-700`}
                          style={{ width: `${Math.max(5, analysisResult.heuristic_score)}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-500 mt-1.5">
                        Static heuristic indicator (not a probability)
                      </span>
                    </div>
                  </div>

                  {/* Parsed Structure Details */}
                  <div className="relative z-10 pt-5 grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-500 block text-[11px]">Scheme:</span>
                      <span
                        className={`font-semibold ${
                          analysisResult.scheme === 'https' ? 'text-emerald-400' : 'text-amber-400'
                        }`}
                      >
                        {analysisResult.scheme}://
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-500 block text-[11px]">Registered Domain:</span>
                      <span className="text-cyan-300 font-semibold truncate block" title={analysisResult.registered_domain}>
                        {analysisResult.registered_domain || 'N/A'}
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60 sm:col-span-2 flex items-center justify-between">
                      <div className="truncate mr-2">
                        <span className="text-slate-500 block text-[11px]">Full Target Host:</span>
                        <span className="text-slate-200 font-semibold truncate block" title={analysisResult.hostname}>
                          {analysisResult.hostname}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          onClick={() => copyUrl(analysisResult.submitted_url)}
                          className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                          title="Copy submitted URL"
                        >
                          {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => copyDefangedUrl(analysisResult.submitted_url)}
                          className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                          title="Copy defanged URL (hxxp[://]...)"
                        >
                          {copiedDefanged ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <EyeOff className="w-3.5 h-3.5 text-slate-400" />}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Action Toolbar for Report */}
                  <div className="relative z-10 pt-4 mt-4 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800">
                      <button
                        onClick={() => setActiveDetailTab('findings')}
                        className={`px-3 py-1 rounded-md font-medium transition cursor-pointer ${
                          activeDetailTab === 'findings'
                            ? 'bg-slate-800 text-cyan-300 shadow-sm'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Findings ({analysisResult.findings.length})
                      </button>
                      <button
                        onClick={() => setActiveDetailTab('structure')}
                        className={`px-3 py-1 rounded-md font-medium transition cursor-pointer ${
                          activeDetailTab === 'structure'
                            ? 'bg-slate-800 text-cyan-300 shadow-sm'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Lexical Breakdown
                      </button>
                      <button
                        onClick={() => setActiveDetailTab('ioc')}
                        className={`px-3 py-1 rounded-md font-medium transition cursor-pointer ${
                          activeDetailTab === 'ioc'
                            ? 'bg-slate-800 text-cyan-300 shadow-sm'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        SOC Indicators (IOC)
                      </button>
                      <button
                        onClick={() => setActiveDetailTab('json')}
                        className={`px-3 py-1 rounded-md font-medium transition cursor-pointer ${
                          activeDetailTab === 'json'
                            ? 'bg-slate-800 text-cyan-300 shadow-sm'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        JSON
                      </button>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={copyReportJson}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 transition cursor-pointer"
                      >
                        {copiedJson ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Copied JSON</span>
                          </>
                        ) : (
                          <>
                            <Share2 className="w-3.5 h-3.5 text-slate-400" />
                            <span>Copy Report</span>
                          </>
                        )}
                      </button>
                      <button
                        onClick={downloadReportJson}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 transition cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5 text-slate-400" />
                        <span>Export JSON</span>
                      </button>
                      <button
                        onClick={() => setAnalysisResult(null)}
                        className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                      >
                        Dashboard
                      </button>
                    </div>
                  </div>
                </section>

                {/* TAB CONTENT: Findings Breakdown */}
                {activeDetailTab === 'findings' && (
                  <section className="flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                          <Terminal className="w-5 h-5 text-cyan-400" />
                          Explainable Heuristic Breakdown
                        </h3>
                        <p className="text-xs text-slate-400">
                          Transparent examination of individual lexical flags, syntax indicators, and score weights
                        </p>
                      </div>
                      <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800/90 text-slate-300">
                        {analysisResult.findings.length} Finding{analysisResult.findings.length === 1 ? '' : 's'}
                      </span>
                    </div>

                    <div className="flex flex-col gap-3">
                      {analysisResult.findings.map((finding) => {
                        const isExpanded = !!expandedFindings[finding.rule_id]
                        const isHigh = finding.severity === 'high'
                        const isMed = finding.severity === 'medium'
                        const isLow = finding.severity === 'low'

                        const severityBadgeClass = isHigh
                          ? 'bg-rose-950/60 border-rose-800/80 text-rose-300'
                          : isMed
                          ? 'bg-amber-950/60 border-amber-800/80 text-amber-300'
                          : isLow
                          ? 'bg-blue-950/60 border-blue-800/80 text-blue-300'
                          : 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'

                        return (
                          <div
                            key={finding.rule_id}
                            className="rounded-xl border border-slate-800 bg-[#0c101c] overflow-hidden transition hover:border-slate-700"
                          >
                            <button
                              type="button"
                              onClick={() => toggleFinding(finding.rule_id)}
                              className="w-full p-4 flex items-center justify-between gap-4 text-left cursor-pointer hover:bg-slate-900/30 transition"
                            >
                              <div className="flex items-center gap-3 flex-1 min-w-0">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border shrink-0 ${severityBadgeClass}`}
                                >
                                  {finding.severity}
                                </span>
                                <span className="font-semibold text-sm text-slate-200 truncate">
                                  {finding.title}
                                </span>
                                <span className="text-xs font-mono text-slate-500 hidden sm:inline">
                                  [{finding.rule_id}]
                                </span>
                              </div>

                              <div className="flex items-center gap-3 shrink-0">
                                <span
                                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                                    finding.score_impact > 0
                                      ? isHigh
                                        ? 'bg-rose-950/50 text-rose-400 border border-rose-900'
                                        : 'bg-amber-950/50 text-amber-400 border border-amber-900'
                                      : 'bg-slate-800 text-slate-400'
                                  }`}
                                >
                                  +{finding.score_impact} pts
                                </span>
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4 text-slate-500" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-slate-500" />
                                )}
                              </div>
                            </button>

                            {isExpanded && (
                              <div className="px-4 pb-4 pt-1 border-t border-slate-800/60 flex flex-col gap-3 text-xs bg-[#090d18]/40">
                                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-slate-300">
                                  <span className="text-slate-500 block text-[10px] uppercase font-semibold">
                                    Observed Evidence:
                                  </span>
                                  <span className="text-cyan-300 break-all">{finding.evidence}</span>
                                </div>

                                <div>
                                  <span className="text-slate-400 font-semibold block mb-1">
                                    Why this matters:
                                  </span>
                                  <p className="text-slate-300 leading-relaxed">
                                    {finding.explanation}
                                  </p>
                                </div>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </section>
                )}

                {/* TAB CONTENT: Lexical Structure Breakdown */}
                {activeDetailTab === 'structure' && (
                  <section className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-5">
                    <div className="flex items-center gap-2 text-white font-bold text-base">
                      <Code2 className="w-5 h-5 text-cyan-400" />
                      <span>RFC 3986 Component Decomposition</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Normalized URL</span>
                        <span className="text-slate-200 break-all select-all">{analysisResult.normalized_url}</span>
                      </div>
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Hostname</span>
                        <span className="text-cyan-300 break-all select-all">{analysisResult.hostname}</span>
                      </div>
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Registered Domain</span>
                        <span className="text-emerald-300 break-all select-all">{analysisResult.registered_domain || 'None (IP literal or single token)'}</span>
                      </div>
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Target Path</span>
                        <span className="text-slate-200 break-all select-all">{analysisResult.path || '/'}</span>
                      </div>
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Subdomain Hierarchy</span>
                        <span className="text-slate-300 break-all select-all">
                          {analysisResult.components?.subdomains?.length ? analysisResult.components.subdomains.join('.') : 'None'}
                        </span>
                      </div>
                      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800">
                        <span className="text-slate-500 text-[10px] uppercase block">Domain Label Entropy</span>
                        <span className="text-cyan-300 break-all select-all">
                          {analysisResult.components?.entropy} bits (Threshold: &gt; 3.60)
                        </span>
                      </div>
                    </div>

                    {/* Query parameters list if any */}
                    {analysisResult.components?.query_params && Object.keys(analysisResult.components.query_params).length > 0 && (
                      <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800 flex flex-col gap-2">
                        <span className="text-xs font-bold text-slate-300">Parsed Query String Parameters:</span>
                        <div className="divide-y divide-slate-800 text-xs font-mono">
                          {Object.entries(analysisResult.components.query_params).map(([k, v]) => (
                            <div key={k} className="py-1.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                              <span className="text-amber-400 font-semibold">{k}</span>
                              <span className="text-slate-300 break-all">{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </section>
                )}

                {/* TAB CONTENT: SOC Indicators (IOC) */}
                {activeDetailTab === 'ioc' && (
                  <section className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-white font-bold text-base">
                        <Shield className="w-5 h-5 text-cyan-400" />
                        <span>Security Operations Center (SOC) IOC Block</span>
                      </div>
                      <button
                        onClick={() => {
                          const iocText = `[URLIX Threat Intelligence IOC]
URL (Defanged): ${defangUrl(analysisResult.submitted_url)}
Hostname: ${analysisResult.hostname}
Registered Domain: ${analysisResult.registered_domain}
Risk Verdict: ${analysisResult.risk_category} (${analysisResult.heuristic_score}/100)
Detected Flags: ${analysisResult.threat_tags?.join(', ') || 'None'}
Timestamp UTC: ${analysisResult.analyzed_at}`
                          navigator.clipboard.writeText(iocText)
                          alert('IOC block copied to clipboard!')
                        }}
                        className="px-3 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300 transition cursor-pointer"
                      >
                        Copy Incident IOC
                      </button>
                    </div>

                    <div className="p-4 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
                      <div><strong className="text-slate-500">Defanged Link:</strong> <span className="text-rose-300 select-all">{defangUrl(analysisResult.submitted_url)}</span></div>
                      <div><strong className="text-slate-500">Target Host:</strong> <span className="text-slate-200 select-all">{analysisResult.hostname}</span></div>
                      <div><strong className="text-slate-500">Registered Root Domain:</strong> <span className="text-cyan-300 select-all">{analysisResult.registered_domain}</span></div>
                      <div><strong className="text-slate-500">Risk Severity:</strong> <span className={analysisResult.risk_category === 'High' ? 'text-rose-400 font-bold' : 'text-amber-400'}>{analysisResult.risk_category} Risk ({analysisResult.heuristic_score}/100)</span></div>
                      <div><strong className="text-slate-500">Categorization Tags:</strong> <span className="text-slate-300">{analysisResult.threat_tags?.join(' | ') || 'None'}</span></div>
                      <div><strong className="text-slate-500">Observation Time:</strong> <span className="text-slate-400">{analysisResult.analyzed_at}</span></div>
                    </div>
                  </section>
                )}

                {/* TAB CONTENT: Raw JSON */}
                {activeDetailTab === 'json' && (
                  <section className="rounded-2xl bg-[#0b0f19] border border-slate-800 p-6 flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Raw Machine-Readable JSON</span>
                      <button
                        onClick={copyReportJson}
                        className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
                      >
                        <Copy className="w-3.5 h-3.5" /> Copy JSON
                      </button>
                    </div>
                    <pre className="p-4 rounded-xl bg-[#07090e] border border-slate-800/80 font-mono text-xs text-cyan-300/90 overflow-x-auto max-h-96">
                      {JSON.stringify(analysisResult, null, 2)}
                    </pre>
                  </section>
                )}

                {/* Actionable Next Steps & Security Recommendations */}
                <section className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
                  <div className="flex items-center gap-2 text-white font-bold text-base">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span>Actionable Security Recommendations</span>
                  </div>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-slate-300">
                    {analysisResult.recommendations.map((rec, i) => (
                      <li
                        key={i}
                        className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/70 flex items-start gap-2.5 leading-relaxed"
                      >
                        <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </section>

                {/* Safety & Heuristic Disclaimer */}
                <section className="p-4 rounded-xl bg-[#090c14] border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div className="leading-relaxed">
                    <strong className="text-slate-300 font-semibold">Important Security Notice: </strong>
                    {analysisResult.disclaimer}
                  </div>
                </section>
              </div>
            )}
          </>
        )}

        {/* ========================================================= */}
        {/* TAB 2: BATCH & EMAIL EXTRACTOR */}
        {/* ========================================================= */}
        {activeMainTab === 'batch' && (
          <section className="flex flex-col gap-6">
            <div>
              <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                <FileSpreadsheet className="w-6 h-6 text-cyan-400" />
                Batch & Email Link Extractor
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Paste raw email bodies, SMS messages, or bulk link lists. URLIX automatically extracts all hyperlinks and passively scores each target link.
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Raw Text / Email Payload / URL List</span>
                <span className="text-slate-500 font-normal">Supports markdown, hxxp defanged, and plain URLs</span>
              </label>

              <textarea
                value={rawBatchText}
                onChange={(e) => setRawBatchText(e.target.value)}
                rows={6}
                placeholder={`Paste suspected email text or URL lists, e.g.:

Dear customer, please review your transaction at http://login.microsoft.com.secure-auth-update.xyz/auth.php immediately.
Backup link: https://paypal.com@evil-phish.top/account-verify
Official portal: https://github.com/explore`}
                className="w-full p-4 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/80"
              />

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleBatchAnalyze}
                    disabled={batchAnalyzing || !rawBatchText.trim()}
                    className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 text-slate-950 font-bold text-xs tracking-wide shadow-md transition disabled:opacity-50 cursor-pointer flex items-center gap-2"
                  >
                    {batchAnalyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    <span>Extract & Scan Links</span>
                  </button>

                  <button
                    onClick={() => {
                      setRawBatchText(`URGENT NOTICE:
Please confirm your account login at:
http://login.microsoft.com.secure-auth-update.xyz/auth.php
Payment dispute filed:
https://paypal.com@evil-phish.top/account-verify
Support patch download:
https://bankofamerica-secure-login-update.com/patch/update.exe
Legitimate documentation:
https://github.com/explore`)
                    }}
                    className="px-3 py-2 rounded-xl border border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 text-xs transition cursor-pointer"
                  >
                    Load Sample Email
                  </button>
                </div>

                {batchResults.length > 0 && (
                  <button
                    onClick={exportBatchCsv}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl border border-cyan-800 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 text-xs font-semibold transition cursor-pointer"
                  >
                    {copiedBatchCsv ? <Check className="w-3.5 h-3.5" /> : <Download className="w-3.5 h-3.5" />}
                    <span>Export CSV Report</span>
                  </button>
                )}
              </div>
            </div>

            {/* Batch Results Table */}
            {batchResults.length > 0 && (
              <div className="flex flex-col gap-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-4 rounded-xl bg-[#0b0f19] border border-slate-800 text-center">
                    <span className="text-[10px] text-slate-500 uppercase font-bold">Extracted URLs</span>
                    <span className="text-2xl font-extrabold text-white block mt-1">{batchResults.length}</span>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b0f19] border border-rose-900/50 text-center">
                    <span className="text-[10px] text-rose-500 uppercase font-bold">High Risk Links</span>
                    <span className="text-2xl font-extrabold text-rose-400 block mt-1">
                      {batchResults.filter((b) => b.risk_category === 'High').length}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b0f19] border border-amber-900/50 text-center">
                    <span className="text-[10px] text-amber-500 uppercase font-bold">Medium Risk Links</span>
                    <span className="text-2xl font-extrabold text-amber-400 block mt-1">
                      {batchResults.filter((b) => b.risk_category === 'Medium').length}
                    </span>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b0f19] border border-emerald-900/50 text-center">
                    <span className="text-[10px] text-emerald-500 uppercase font-bold">Low Risk Links</span>
                    <span className="text-2xl font-extrabold text-emerald-400 block mt-1">
                      {batchResults.filter((b) => b.risk_category === 'Low').length}
                    </span>
                  </div>
                </div>

                <div className="overflow-hidden rounded-2xl border border-slate-800 bg-[#0b0f19]">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm border-collapse">
                      <thead>
                        <tr className="bg-slate-900/50 border-b border-slate-800 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                          <th className="px-6 py-4">Extracted Target URL</th>
                          <th className="px-6 py-4">Verdict</th>
                          <th className="px-6 py-4">Heuristic Score</th>
                          <th className="px-6 py-4">Primary Threats</th>
                          <th className="px-6 py-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/50 text-xs">
                        {batchResults.map((item, idx) => {
                          const theme = getRiskTheme(item.risk_category)
                          return (
                            <tr key={idx} className="hover:bg-slate-800/30 transition">
                              <td className="px-6 py-4 max-w-sm">
                                <span className="font-mono text-slate-200 truncate block" title={item.submitted_url}>
                                  {item.submitted_url}
                                </span>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${theme.badge}`}>
                                  {item.risk_category}
                                </span>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                <span className={`font-mono font-bold ${theme.scoreText}`}>{item.heuristic_score}/100</span>
                              </td>
                              <td className="px-6 py-4">
                                <div className="flex flex-wrap gap-1">
                                  {item.threat_tags?.map((t) => (
                                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                                      {t}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-6 py-4 text-right whitespace-nowrap">
                                <button
                                  onClick={() => {
                                    setAnalysisResult(item)
                                    setActiveMainTab('inspector')
                                    window.scrollTo({ top: 0, behavior: 'smooth' })
                                  }}
                                  className="text-cyan-400 hover:text-cyan-300 font-bold cursor-pointer"
                                >
                                  Deep Dive →
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* ========================================================= */}
        {/* TAB 3: QUISHING DEFENSE (QR CODE SCANNER) */}
        {/* ========================================================= */}
        {activeMainTab === 'quishing' && (
          <section className="flex flex-col gap-6">
            <div>
              <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                <QrCode className="w-6 h-6 text-cyan-400" />
                Quishing Defense (QR Code Phishing Scanner)
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Attackers place deceptive QR codes in phishing emails, parking meters, and flyers to bypass email security gateways. Safely decode and scan QR targets without opening them on your mobile device.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* File upload dropzone */}
              <div
                onClick={() => qrFileInputRef.current?.click()}
                className="p-8 rounded-2xl bg-[#0b0f19] border-2 border-dashed border-slate-700 hover:border-cyan-500/80 transition cursor-pointer flex flex-col items-center justify-center text-center gap-3"
              >
                <input
                  ref={qrFileInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) handleQrUpload(file)
                  }}
                />
                <div className="p-4 rounded-2xl bg-cyan-950/40 border border-cyan-800/60 text-cyan-400">
                  <UploadCloud className="w-8 h-8" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-200 text-sm">Upload QR Code Image</h3>
                  <p className="text-xs text-slate-500 mt-1">Click to browse or drop PNG, JPEG, WEBP</p>
                </div>
                {qrDecoding && (
                  <div className="flex items-center gap-2 text-xs text-cyan-400 animate-pulse mt-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Decoding QR pattern...</span>
                  </div>
                )}
              </div>

              {/* Quick sample tests */}
              <div className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col justify-between gap-4">
                <div>
                  <h3 className="font-bold text-white text-sm">Or Test With Sample Threat QRs</h3>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    Test how URLIX safely handles embedded QR codes without triggering mobile browser navigation.
                  </p>
                </div>

                <div className="flex flex-col gap-2.5">
                  <button
                    onClick={() => handleTestQrSample('phish')}
                    className="p-3 rounded-xl border border-rose-900/50 bg-rose-950/20 hover:bg-rose-950/40 text-left transition cursor-pointer flex items-center justify-between"
                  >
                    <div>
                      <span className="text-xs font-bold text-rose-300 block">Sample Quishing Attack QR</span>
                      <span className="text-[11px] font-mono text-slate-500">Deceptive authority @ trick embedded</span>
                    </div>
                    <span className="text-xs text-rose-400 font-bold">Simulate & Analyze →</span>
                  </button>

                  <button
                    onClick={() => handleTestQrSample('legit')}
                    className="p-3 rounded-xl border border-emerald-900/50 bg-emerald-950/20 hover:bg-emerald-950/40 text-left transition cursor-pointer flex items-center justify-between"
                  >
                    <div>
                      <span className="text-xs font-bold text-emerald-300 block">Sample Benign QR Code</span>
                      <span className="text-[11px] font-mono text-slate-500">Official legitimate repository destination</span>
                    </div>
                    <span className="text-xs text-emerald-400 font-bold">Simulate & Analyze →</span>
                  </button>
                </div>

                {qrError && (
                  <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                    <XCircle className="w-4 h-4 shrink-0" />
                    <span>{qrError}</span>
                  </div>
                )}

                {decodedQrUrl && (
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs font-mono">
                    <span className="text-slate-500 block text-[10px] uppercase">Decoded URL Target:</span>
                    <span className="text-cyan-300 break-all">{decodedQrUrl}</span>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* ========================================================= */}
        {/* TAB 4: SOC URL DEFANGER & REFANGER */}
        {/* ========================================================= */}
        {activeMainTab === 'defanger' && (
          <section className="flex flex-col gap-6">
            <div>
              <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                <EyeOff className="w-6 h-6 text-cyan-400" />
                SOC Analyst URL Defanger & Safe Sharing Tool
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Defang suspicious URLs (turning <code className="text-cyan-300">https://</code> into <code className="text-cyan-300">hxxps[://]</code> and dots into <code className="text-cyan-300">[.]</code>) to safely paste them in Jira tickets, Slack, or email without accidental clicks.
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setDefangMode('defang')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    defangMode === 'defang' ? 'bg-cyan-950 border border-cyan-800 text-cyan-300' : 'text-slate-400'
                  }`}
                >
                  Defang (Make Safe)
                </button>
                <button
                  onClick={() => setDefangMode('refang')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    defangMode === 'refang' ? 'bg-cyan-950 border border-cyan-800 text-cyan-300' : 'text-slate-400'
                  }`}
                >
                  Refang (Restore Original)
                </button>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Input URL:</label>
                <input
                  type="text"
                  value={defangInput}
                  onChange={(e) => setDefangInput(e.target.value)}
                  className="w-full p-3 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs text-slate-400">Processed Output:</label>
                  <button
                    onClick={() => {
                      const res = defangMode === 'defang' ? defangUrl(defangInput) : refangUrl(defangInput)
                      navigator.clipboard.writeText(res)
                      setCopiedDefangResult(true)
                      setTimeout(() => setCopiedDefangResult(false), 2000)
                    }}
                    className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
                  >
                    {copiedDefangResult ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedDefangResult ? 'Copied!' : 'Copy'}</span>
                  </button>
                </div>
                <div className="p-3.5 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-cyan-300 break-all select-all">
                  {defangMode === 'defang' ? defangUrl(defangInput) : refangUrl(defangInput)}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ========================================================= */}
        {/* TAB 5: DOMAIN CLONE COMPARATOR */}
        {/* ========================================================= */}
        {activeMainTab === 'compare' && (
          <section className="flex flex-col gap-6">
            <div>
              <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                <GitCompare className="w-6 h-6 text-cyan-400" />
                Side-by-Side Domain Clone Comparator
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Compare suspected phishing clone links directly against official legitimate services to spotlight homographs, entropy gaps, and rogue root domains.
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-emerald-400 block mb-1">Target A (e.g. Official Site):</label>
                  <input
                    type="text"
                    value={compareUrlA}
                    onChange={(e) => setCompareUrlA(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-rose-400 block mb-1">Target B (e.g. Suspected Clone):</label>
                  <input
                    type="text"
                    value={compareUrlB}
                    onChange={(e) => setCompareUrlB(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-[#07090e] border border-slate-800 font-mono text-xs text-slate-200"
                  />
                </div>
              </div>

              <button
                onClick={handleRunComparison}
                className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 text-slate-950 font-bold text-xs tracking-wide shadow-md transition cursor-pointer"
              >
                Compare Heuristic Profiles
              </button>
            </div>

            {/* Comparison Side-by-Side Table */}
            {comparisonResultA && comparisonResultB && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Result A */}
                <div className="p-6 rounded-2xl bg-[#0b0f19] border border-slate-800 flex flex-col gap-4">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <span className="text-xs font-bold text-emerald-400 uppercase">Profile A (Legitimate)</span>
                    <span className="font-mono text-sm font-bold text-white">{comparisonResultA.heuristic_score}/100</span>
                  </div>
                  <div className="space-y-2 text-xs font-mono">
                    <div><span className="text-slate-500 block">Host:</span> <span className="text-slate-200 break-all">{comparisonResultA.hostname}</span></div>
                    <div><span className="text-slate-500 block">Root Domain:</span> <span className="text-emerald-300 break-all">{comparisonResultA.registered_domain}</span></div>
                    <div><span className="text-slate-500 block">Entropy:</span> <span className="text-slate-200">{comparisonResultA.components?.entropy} bits</span></div>
                    <div><span className="text-slate-500 block">Risk Category:</span> <span className="text-emerald-400 font-bold">{comparisonResultA.risk_category}</span></div>
                    <div><span className="text-slate-500 block">Findings:</span> <span className="text-slate-300">{comparisonResultA.findings.length} observed</span></div>
                  </div>
                </div>

                {/* Result B */}
                <div className="p-6 rounded-2xl bg-[#0b0f19] border border-rose-900/50 flex flex-col gap-4">
                  <div className="flex items-center justify-between pb-3 border-b border-rose-900/60">
                    <span className="text-xs font-bold text-rose-400 uppercase">Profile B (Suspect)</span>
                    <span className="font-mono text-sm font-bold text-rose-400">{comparisonResultB.heuristic_score}/100</span>
                  </div>
                  <div className="space-y-2 text-xs font-mono">
                    <div><span className="text-slate-500 block">Host:</span> <span className="text-rose-200 break-all">{comparisonResultB.hostname}</span></div>
                    <div><span className="text-slate-500 block">Root Domain:</span> <span className="text-rose-300 break-all">{comparisonResultB.registered_domain}</span></div>
                    <div><span className="text-slate-500 block">Entropy:</span> <span className="text-slate-200">{comparisonResultB.components?.entropy} bits</span></div>
                    <div><span className="text-slate-500 block">Risk Category:</span> <span className="text-rose-400 font-bold">{comparisonResultB.risk_category}</span></div>
                    <div><span className="text-slate-500 block">Findings:</span> <span className="text-rose-300">{comparisonResultB.findings.length} observed</span></div>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Live System Diagnostics (Telemetry section preserved) */}
        <section className="bg-[#0b0f1a] border border-slate-800 rounded-2xl p-6 shadow-xl mt-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-950/50 border border-cyan-800/50 text-cyan-400">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  URLIX Engine Status & Telemetry
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono font-normal">
                    GET /api/health
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Explainable Heuristic Detection Engine connected at /api/analyze
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchHealth}
                className="px-3 py-1.5 text-xs rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition cursor-pointer"
              >
                <RefreshCw className={`w-3 h-3 ${loadingHealth ? 'animate-spin' : ''}`} />
                <span>Test Ping</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5">
            <div className="p-4 rounded-xl bg-[#080b13] border border-slate-800/80 flex flex-col gap-1">
              <span className="text-xs text-slate-400 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" /> Detection Engine
              </span>
              <span className="text-sm font-semibold capitalize mt-1 flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                {health?.detection_engine || (loadingHealth ? 'Querying...' : 'Active')}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#080b13] border border-slate-800/80 flex flex-col gap-1">
              <span className="text-xs text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-teal-400" /> Server Uptime
              </span>
              <span className="text-sm font-semibold font-mono text-slate-200 mt-1">
                {health ? `${health.uptime_seconds}s` : '---'}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#080b13] border border-slate-800/80 flex flex-col gap-1">
              <span className="text-xs text-slate-400 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" /> Round-Trip Latency
              </span>
              <span className="text-sm font-semibold font-mono text-cyan-300 mt-1">
                {pingLatency !== null ? `${pingLatency} ms` : '---'}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#080b13] border border-slate-800/80 flex flex-col gap-1">
              <span className="text-xs text-slate-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Engine Version
              </span>
              <span className="text-sm font-semibold font-mono text-slate-200 mt-1">
                {health ? `v${health.version}` : '---'}
              </span>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#080b13] py-6 text-center text-xs text-slate-500">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>URLIX — Phishing & Malicious Link Detection Engine • Zero-Execution Heuristics</p>
          <div className="flex items-center gap-4 text-[11px] text-slate-500">
            <span>RFC 3986 Syntax Compliant</span>
            <span>•</span>
            <span>Passive Lexical Intelligence</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
