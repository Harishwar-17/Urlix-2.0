export interface Finding {
  rule_id: string
  title: string
  severity: 'info' | 'low' | 'medium' | 'high'
  score_impact: number
  evidence: string
  explanation: string
}

export interface ComponentBreakdown {
  scheme: string
  username?: string
  password?: string
  subdomains: string[]
  registered_domain: string
  tld: string
  port?: string
  path: string
  query_params: Record<string, string>
  hash: string
  is_ip: boolean
  entropy: number
}

export interface AnalyzeResponse {
  submitted_url: string
  normalized_url: string
  scheme: string
  hostname: string
  registered_domain: string
  path: string
  risk_category: 'Low' | 'Medium' | 'High'
  heuristic_score: number
  score_description: string
  summary: string
  findings_count: number
  findings: Finding[]
  recommendations: string[]
  disclaimer: string
  analyzed_at: string
  passive_analysis: boolean
  threat_tags?: string[]
  components?: ComponentBreakdown
  defanged_url?: string
}

// Common brand identifiers frequently spoofed in phishing attacks
export const WELL_KNOWN_BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'accounts.google.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com'],
  meta: ['meta.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  dropbox: ['dropbox.com'],
  yahoo: ['yahoo.com'],
  linkedin: ['linkedin.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  adobe: ['adobe.com'],
  ebay: ['ebay.com'],
  twitter: ['twitter.com', 'x.com'],
  spotify: ['spotify.com'],
}

// Known public URL shorteners
export const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  'is.gd',
  't.co',
  'ow.ly',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
  'soo.gd',
  's.id',
  't.ly',
  'v.gd',
  'tiny.cc',
  'bl.ink',
  'rotf.lol',
])

// TLDs historically characterized by high abuse ratios in disposable campaigns
export const HIGH_ABUSE_TLDS = new Set([
  'top',
  'xyz',
  'club',
  'work',
  'click',
  'buzz',
  'surf',
  'monster',
  'fit',
  'rest',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'gdn',
  'stream',
  'cam',
  'kim',
  'country',
  'win',
  'bid',
  'link',
  'mom',
])

// Sensitive credential / transaction keywords
export const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'log-in',
  'verify',
  'verification',
  'account',
  'banking',
  'security',
  'update',
  'wallet',
  'confirm',
  'confirmation',
  'password',
  'support',
  'billing',
  'authenticate',
  'recover',
  'secure-login',
  'auth',
  'credential',
  'invoice',
  'session-token',
  'unlock',
  'dispute',
]

// High-risk file extensions in path
export const MALICIOUS_EXTENSIONS = [
  '.exe',
  '.scr',
  '.bat',
  '.cmd',
  '.msi',
  '.vbs',
  '.vbe',
  '.js',
  '.jse',
  '.wsf',
  '.wsh',
  '.ps1',
  '.hta',
  '.jar',
  '.iso',
  '.img',
  '.dll',
  '.pif',
  '.apk',
]

// Suspicious open redirect query parameters
export const REDIRECT_QUERY_PARAMS = [
  'redirect',
  'redirect_uri',
  'redirect_url',
  'url',
  'next',
  'dest',
  'destination',
  'target',
  'link',
  'return_to',
  'goto',
  'out',
  'to',
]

/**
 * Calculates Shannon entropy of a string (character randomness measure).
 */
export function calculateShannonEntropy(text: string): number {
  if (!text) return 0.0
  const freq: Record<string, number> = {}
  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    freq[char] = (freq[char] || 0) + 1
  }
  let entropy = 0.0
  const length = text.length
  for (const count of Object.values(freq)) {
    const p = count / length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * Levenshtein distance between two strings
 */
export function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = []
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i]
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(
            matrix[i][j - 1] + 1, // insertion
            matrix[i - 1][j] + 1 // deletion
          )
        )
      }
    }
  }
  return matrix[b.length][a.length]
}

/**
 * Checks if a hostname is an explicit IPv4 or IPv6 address.
 */
export function isIpAddress(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '').trim()
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const match = ipv4Regex.exec(clean)
  if (match) {
    const parts = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])]
    return parts.every((p) => p >= 0 && p <= 255)
  }
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
  return ipv6Regex.test(clean)
}

/**
 * Extracts registered domain, TLD, and subdomain list from hostname.
 */
export function extractDomainParts(hostname: string): {
  registeredDomain: string
  tld: string
  subdomains: string[]
} {
  const cleanHost = hostname.toLowerCase().trim()
  const parts = cleanHost.split('.')
  if (parts.length <= 1) {
    return { registeredDomain: cleanHost, tld: '', subdomains: [] }
  }

  const tld = parts[parts.length - 1]
  const secondLast = parts[parts.length - 2]
  if (
    parts.length >= 3 &&
    ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(secondLast) &&
    tld.length === 2
  ) {
    const registeredDomain = `${parts[parts.length - 3]}.${secondLast}.${tld}`
    const subdomains = parts.slice(0, -3)
    return { registeredDomain, tld, subdomains }
  }

  const registeredDomain = `${secondLast}.${tld}`
  const subdomains = parts.slice(0, -2)
  return { registeredDomain, tld, subdomains }
}

/**
 * Safely defangs a URL to prevent accidental clicks in chat / tickets.
 * e.g., https://evil.com/login -> hxxps[://]evil[.]com/login
 */
export function defangUrl(rawUrl: string): string {
  if (!rawUrl) return ''
  return rawUrl
    .replace(/^https:\/\//i, 'hxxps[://]')
    .replace(/^http:\/\//i, 'hxxp[://]')
    .replace(/@/g, '[@]')
    .replace(/\./g, '[.]')
}

/**
 * Restores a defanged URL back to standard format.
 */
export function refangUrl(defanged: string): string {
  if (!defanged) return ''
  return defanged
    .replace(/^hxxps\[:\/\/\]/i, 'https://')
    .replace(/^hxxp\[:\/\/\]/i, 'http://')
    .replace(/\[@\]/g, '@')
    .replace(/\[\.\]/g, '.')
}

/**
 * Extracts all URLs from arbitrary text or email message.
 */
export function extractUrlsFromText(text: string): string[] {
  if (!text) return []
  // Matches http, https, hxxp, hxxps, and raw www. domains
  const urlRegex = /(?:https?|hxxps?):\/\/[^\s<>"'{}|\\^`]+|(?:\bwww\.[^\s<>"'{}|\\^`]+\.[a-z]{2,})/gi
  const matches = text.match(urlRegex) || []
  const uniqueUrls = Array.from(new Set(matches.map((u) => refangUrl(u.trim()))))
  return uniqueUrls
}

/**
 * Validates URL syntax strictly:
 * - Must be non-empty string.
 * - Must have http or https scheme.
 * - Hostname must be present and valid.
 * - Never triggers network lookups or fetches.
 */
export function validateUrlSyntax(rawUrl: string): {
  valid: boolean
  error?: string
  parsed?: URL
  urlStr?: string
} {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'Input must be a non-empty string.' }
  }

  let urlStr = refangUrl(rawUrl.trim())
  if (urlStr.length === 0) {
    return { valid: false, error: 'URL parameter is required and cannot be empty.' }
  }

  if (urlStr.length > 2048) {
    return { valid: false, error: 'URL exceeds maximum permitted length of 2048 characters.' }
  }

  const forbiddenSchemes = ['javascript:', 'data:', 'file:', 'vbscript:', 'about:']
  const lowerUrl = urlStr.toLowerCase()
  if (forbiddenSchemes.some((s) => lowerUrl.startsWith(s))) {
    return {
      valid: false,
      error: 'Scheme not supported. Only HTTP and HTTPS URLs are accepted for analysis.',
    }
  }

  if (!lowerUrl.startsWith('http://') && !lowerUrl.startsWith('https://')) {
    if (urlStr.includes('://')) {
      const scheme = urlStr.split('://')[0].toLowerCase()
      return {
        valid: false,
        error: `Unsupported URL scheme '${scheme}'. Only http and https are analyzed.`,
      }
    }
    urlStr = 'http://' + urlStr
  }

  try {
    const parsed = new URL(urlStr)
    const scheme = parsed.protocol.replace(':', '').toLowerCase()
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        valid: false,
        error: `Invalid scheme '${scheme}'. Only http and https URLs are accepted.`,
      }
    }

    if (!parsed.hostname) {
      return { valid: false, error: 'Unable to extract a valid hostname from the URL.' }
    }

    return { valid: true, parsed, urlStr }
  } catch (err: any) {
    return { valid: false, error: `Malformed URL syntax: ${err.message || 'Invalid format'}` }
  }
}

/**
 * URLIX Explainable Heuristic Detection Engine.
 * Executes purely passive lexical and structural inspection.
 */
export function analyzeUrl(rawUrl: string): AnalyzeResponse {
  const validation = validateUrlSyntax(rawUrl)
  if (!validation.valid || !validation.parsed) {
    throw new Error(validation.error || 'Invalid URL')
  }

  const parsed = validation.parsed
  const originalUrl = rawUrl.trim()
  const scheme = parsed.protocol.replace(':', '').toLowerCase()
  const rawHostname = parsed.hostname.toLowerCase()
  const pathname = parsed.pathname || ''
  const search = parsed.search || ''
  const hash = parsed.hash || ''
  const fullPath = pathname + search

  // Extract query parameters
  const queryParams: Record<string, string> = {}
  try {
    parsed.searchParams.forEach((val, key) => {
      queryParams[key] = val
    })
  } catch {
    // ignore
  }

  // Check if raw URL had authority credential @ (e.g. https://paypal.com@evil.com)
  const rawAuthorityHasAt = (function () {
    try {
      const match = /^https?:\/\/([^/?#]+)/i.exec(originalUrl)
      if (match && match[1].includes('@')) {
        return true
      }
    } catch {
      // ignore
    }
    return Boolean(parsed.username || parsed.password)
  })()

  const findings: Finding[] = []
  const recommendations: string[] = []
  const threatTags: Set<string> = new Set()
  let rawScore = 0

  const { registeredDomain, tld, subdomains } = extractDomainParts(rawHostname)
  const isIp = isIpAddress(rawHostname)
  const labelEntropy = calculateShannonEntropy(rawHostname)

  // -------------------------------------------------------------
  // Rule 1: HTTP vs HTTPS Transport Encryption
  // -------------------------------------------------------------
  if (scheme === 'http') {
    const scoreImpact = 15
    rawScore += scoreImpact
    threatTags.add('Unencrypted HTTP')
    findings.push({
      rule_id: 'HEUR_UNENCRYPTED_HTTP',
      title: 'Unencrypted HTTP Scheme',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `Protocol scheme is '${scheme}://'`,
      explanation:
        'The URL communicates over unencrypted plaintext HTTP. Modern legitimate sites—particularly those with login or financial interactions—mandate HTTPS encryption. While not all HTTP links are malicious, attackers frequently leverage plain HTTP for transient landing pages.',
    })
    recommendations.push(
      'Never enter passwords, tokens, or financial data on an unencrypted HTTP link.'
    )
  } else {
    findings.push({
      rule_id: 'HEUR_HTTPS_PRESENT',
      title: 'HTTPS Transport Protocol Detected',
      severity: 'info',
      score_impact: 0,
      evidence: "Protocol scheme is 'https://'",
      explanation:
        'The link utilizes HTTPS encryption for transport security. Note that modern phishing sites routinely obtain free SSL/TLS certificates, so HTTPS alone does not prove the website is safe.',
    })
  }

  // -------------------------------------------------------------
  // Rule 2: IP Address in Hostname
  // -------------------------------------------------------------
  if (isIp) {
    const scoreImpact = 35
    rawScore += scoreImpact
    threatTags.add('IP Host')
    findings.push({
      rule_id: 'HEUR_RAW_IP_HOST',
      title: 'Direct IP Address Hostname',
      severity: 'high',
      score_impact: scoreImpact,
      evidence: `Hostname is an explicit IP literal: ${rawHostname}`,
      explanation:
        'The URL directs to a raw numerical IP address instead of a registered domain name. Legitimate commercial organizations almost universally brand through domain names. Attackers frequently use direct IP addresses to evade domain-based reputation filters and blocklists.',
    })
    recommendations.push(
      'Avoid interacting with links hosted directly on raw IP addresses unless connecting to verified internal servers.'
    )
  }

  // -------------------------------------------------------------
  // Rule 3: Misleading Authority Credentials (@ in URL)
  // -------------------------------------------------------------
  if (rawAuthorityHasAt) {
    const scoreImpact = 40
    rawScore += scoreImpact
    threatTags.add('Authority Obfuscation')
    findings.push({
      rule_id: 'HEUR_USERINFO_TRICK',
      title: "Misleading '@' Authority Obfuscation",
      severity: 'high',
      score_impact: scoreImpact,
      evidence: "Contains '@' delimiter within authority component",
      explanation:
        "According to RFC 3986, characters preceding the '@' in the authority component denote userinfo, while modern browsers ignore them and connect exclusively to the server specified AFTER the '@'. This is an adversarial deception tactic used to mimic trusted brands (e.g., 'https://paypal.com@malicious.com').",
    })
    recommendations.push(
      "Treat any URL containing an '@' in the domain component as hostile deception."
    )
  }

  // -------------------------------------------------------------
  // Rule 4: Punycode / Internationalized Domain Name (Homograph Attack)
  // -------------------------------------------------------------
  if (rawHostname.includes('xn--')) {
    const scoreImpact = 30
    rawScore += scoreImpact
    threatTags.add('Punycode Homograph')
    findings.push({
      rule_id: 'HEUR_PUNYCODE_HOMOGRAPH',
      title: 'Punycode IDN Homograph Pattern',
      severity: 'high',
      score_impact: scoreImpact,
      evidence: `Punycode identifier 'xn--' found in domain: ${rawHostname}`,
      explanation:
        'Punycode translates Unicode Internationalized Domain Names (IDNs) into ASCII. Adversaries utilize visually identical characters (homoglyphs from Cyrillic or Greek alphabets) to construct deceptive replicas of well-known domain names.',
    })
    recommendations.push(
      'Inspect the true Unicode rendering of this Punycode domain before trusting its authenticity.'
    )
  }

  // -------------------------------------------------------------
  // Rule 5: Non-standard Port
  // -------------------------------------------------------------
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    const scoreImpact = 15
    rawScore += scoreImpact
    threatTags.add('Non-Standard Port')
    findings.push({
      rule_id: 'HEUR_NON_STANDARD_PORT',
      title: `Non-Standard Communication Port (:${parsed.port})`,
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `Port '${parsed.port}' specified in authority component`,
      explanation:
        'Standard web traffic routes over port 80 (HTTP) or 443 (HTTPS). Non-standard ports are frequently seen in rogue C2 control nodes, staging servers, and disposable phishing kits.',
    })
  }

  // -------------------------------------------------------------
  // Rule 6: Excessively Long URL and Components
  // -------------------------------------------------------------
  const urlLen = originalUrl.length
  if (urlLen > 120) {
    const scoreImpact = 15
    rawScore += scoreImpact
    findings.push({
      rule_id: 'HEUR_EXCESSIVE_URL_LENGTH',
      title: 'Unusually Long URL Length',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `URL length is ${urlLen} characters (standard baseline < 75 chars)`,
      explanation:
        'Excessively long URLs are often engineered to obscure the true domain name in narrow mobile address bars, embed serialized exploit payloads, or bypass standard signature scanners.',
    })
  } else if (urlLen > 75) {
    const scoreImpact = 8
    rawScore += scoreImpact
    findings.push({
      rule_id: 'HEUR_ELEVATED_URL_LENGTH',
      title: 'Elevated URL Length',
      severity: 'low',
      score_impact: scoreImpact,
      evidence: `URL length is ${urlLen} characters`,
      explanation:
        'The URL is longer than typical website links. While common for complex web applications and tracking parameters, elevated length warrants scrutiny.',
    })
  }

  // -------------------------------------------------------------
  // Rule 7: Excessive Subdomain Depth
  // -------------------------------------------------------------
  if (subdomains.length >= 3) {
    const scoreImpact = 20
    rawScore += scoreImpact
    threatTags.add('Deep Subdomains')
    findings.push({
      rule_id: 'HEUR_EXCESSIVE_SUBDOMAINS',
      title: 'Excessive Subdomain Hierarchy',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `${subdomains.length} subdomain layers detected: ${subdomains.join('.')}`,
      explanation:
        'Deep subdomain hierarchies (3 or more levels) are common when attackers use free dynamic DNS services or compromised subdomains to simulate legitimate organizations while masking the real root domain.',
    })
    recommendations.push(
      `Verify whether the actual root domain '${registeredDomain}' is legitimately affiliated with the service.`
    )
  }

  // -------------------------------------------------------------
  // Rule 8: Known URL Shortener
  // -------------------------------------------------------------
  if (
    SHORTENER_DOMAINS.has(rawHostname) ||
    Array.from(SHORTENER_DOMAINS).some((s) => rawHostname.endsWith('.' + s))
  ) {
    const scoreImpact = 18
    rawScore += scoreImpact
    threatTags.add('URL Shortener')
    findings.push({
      rule_id: 'HEUR_URL_SHORTENER',
      title: 'Obfuscated URL Shortening Service',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `Host '${rawHostname}' matches known public shortener service`,
      explanation:
        'URL shortening hides the actual target destination. Attackers frequently use shorteners in SMS/phishing campaigns to bypass automated security gateways and deceive users about the destination host.',
    })
    recommendations.push(
      'Do not click shortened links directly without first previewing the expanded destination.'
    )
  }

  // -------------------------------------------------------------
  // Rule 9: Brand Spoofing / Impersonation & Typosquatting
  // -------------------------------------------------------------
  let userinfoPart = ''
  if (originalUrl.includes('@')) {
    const preAt = originalUrl.split('@')[0]
    const schemeStrip = preAt.replace(/^https?:\/\//i, '')
    userinfoPart = schemeStrip.toLowerCase()
  }

  if (userinfoPart) {
    for (const [brand, legitDomains] of Object.entries(WELL_KNOWN_BRANDS)) {
      if (legitDomains.some((d) => userinfoPart.includes(d))) {
        const isLegitActualHost = legitDomains.some(
          (d) => rawHostname === d || rawHostname.endsWith('.' + d)
        )
        if (!isLegitActualHost) {
          const scoreImpact = 25
          rawScore += scoreImpact
          threatTags.add('Brand Spoofing')
          findings.push({
            rule_id: 'HEUR_BRAND_IN_USERINFO',
            title: `Potential ${brand.charAt(0).toUpperCase() + brand.slice(1)} Brand Deception`,
            severity: 'high',
            score_impact: scoreImpact,
            evidence: `Brand-like text appears before '@', but the actual hostname is '${rawHostname}'`,
            explanation:
              "The URL places a trusted brand name before '@'. The actual destination is the hostname after '@', which does not belong to that brand's listed official domains.",
          })
          recommendations.push(
            `If this link claims to be from ${brand.charAt(0).toUpperCase() + brand.slice(1)}, do not log in. Navigate to the official website directly.`
          )
          break
        }
      }
    }
  }

  // Brand token matching & Typosquatting checks (Levenshtein distance)
  const hostTokens = rawHostname.split(/[-._]/)
  const mainLabel = subdomains.length > 0 ? subdomains[0] : registeredDomain.split('.')[0]
  let brandMatched = false

  for (const [brand, legitDomains] of Object.entries(WELL_KNOWN_BRANDS)) {
    const isLegit = legitDomains.some((ld) => rawHostname === ld || rawHostname.endsWith('.' + ld))
    if (isLegit) continue

    // Exact brand token in hostname
    if (hostTokens.includes(brand)) {
      brandMatched = true
      const scoreImpact = 35
      rawScore += scoreImpact
      threatTags.add('Brand Impersonation')
      findings.push({
        rule_id: 'HEUR_BRAND_IMPERSONATION',
        title: `Potential Brand Impersonation (${brand.charAt(0).toUpperCase() + brand.slice(1)})`,
        severity: 'high',
        score_impact: scoreImpact,
        evidence: `Host '${rawHostname}' includes brand name '${brand}', but registered domain is '${registeredDomain}' (expected official domain: ${legitDomains.join(', ')})`,
        explanation: `The URL references the '${brand.charAt(0).toUpperCase() + brand.slice(1)}' trademark within its hostname or subdomains, yet resolves to an unrelated registered domain ('${registeredDomain}'). This is a primary indicator of phishing sites designed to harvest user account credentials.`,
      })
      recommendations.push(
        `If this link claims to be from ${brand.charAt(0).toUpperCase() + brand.slice(1)}, DO NOT log in. Navigate directly to the official website instead.`
      )
      break
    }

    // Typosquatting check (e.g. "paypa1", "micros0ft", "g00gle")
    if (!brandMatched && mainLabel.length >= 4 && brand.length >= 4) {
      const dist = levenshteinDistance(mainLabel, brand)
      if (dist === 1 || (dist === 2 && brand.length >= 7)) {
        brandMatched = true
        const scoreImpact = 35
        rawScore += scoreImpact
        threatTags.add('Typosquatting')
        findings.push({
          rule_id: 'HEUR_BRAND_TYPOSQUATTING',
          title: `Brand Typosquatting Pattern (${brand.charAt(0).toUpperCase() + brand.slice(1)})`,
          severity: 'high',
          score_impact: scoreImpact,
          evidence: `Domain label '${mainLabel}' is an adversarial variation of brand '${brand}' (Levenshtein distance = ${dist})`,
          explanation: `The domain name closely mimics the famous brand '${brand.charAt(0).toUpperCase() + brand.slice(1)}' with minor character substitutions or omissions. Attackers register lookalike domains to fool human perception.`,
        })
        recommendations.push(
          `Do not trust this link. The domain mimics ${brand.charAt(0).toUpperCase() + brand.slice(1)} through visual deception.`
        )
        break
      }
    }
  }

  // -------------------------------------------------------------
  // Rule 10: Open Redirect Query Parameters
  // -------------------------------------------------------------
  let hasOpenRedirect = false
  for (const [key, val] of Object.entries(queryParams)) {
    if (REDIRECT_QUERY_PARAMS.includes(key.toLowerCase())) {
      if (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('//')) {
        hasOpenRedirect = true
        const scoreImpact = 25
        rawScore += scoreImpact
        threatTags.add('Open Redirect')
        findings.push({
          rule_id: 'HEUR_OPEN_REDIRECT',
          title: 'Suspicious Open Redirect Parameter',
          severity: 'high',
          score_impact: scoreImpact,
          evidence: `Query parameter '${key}' points to external URL: ${val}`,
          explanation:
            'The URL includes an unvalidated destination parameter pointing to an external destination. Attackers abuse open redirect vulnerabilities on benign servers to bounce victims onto malicious phishkits.',
        })
        recommendations.push(
          'Be cautious of links carrying external redirect parameters. Verify the target destination before continuing.'
        )
        break
      }
    }
  }

  // -------------------------------------------------------------
  // Rule 11: Base64 or Serialized Data in Query String
  // -------------------------------------------------------------
  const base64Regex = /(?:[A-Za-z0-9+/]{20,}={0,2})/
  if (!hasOpenRedirect && search.length > 25 && base64Regex.test(search)) {
    const scoreImpact = 15
    rawScore += scoreImpact
    threatTags.add('Obfuscated Query')
    findings.push({
      rule_id: 'HEUR_ENCODED_PAYLOAD',
      title: 'Potential Obfuscated / Base64 Encoded Query Payload',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: 'High-density Base64 or serialized character sequence detected in query string',
      explanation:
        'Attackers frequently embed pre-filled victim email addresses, tokenized session states, or obfuscated payloads in base64 within phishing links to tailor landing pages dynamically.',
    })
  }

  // -------------------------------------------------------------
  // Rule 12: Phishing Keywords in Path or Subdomains
  // -------------------------------------------------------------
  const foundKeywords: string[] = []
  const subdomainsStr = subdomains.join('.').toLowerCase()
  const lowerPath = fullPath.toLowerCase()

  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lowerPath.includes(kw) || subdomainsStr.includes(kw)) {
      foundKeywords.push(kw)
    }
  }

  if (foundKeywords.length > 0) {
    const baseKwImpact = Math.min(25, foundKeywords.length * 8)
    rawScore += baseKwImpact
    threatTags.add('Credential Keywords')
    findings.push({
      rule_id: 'HEUR_CREDENTIAL_KEYWORDS',
      title: 'Authentication / Credential Harvesting Keywords',
      severity: baseKwImpact < 20 ? 'medium' : 'high',
      score_impact: baseKwImpact,
      evidence: `Sensitive keywords detected: ${foundKeywords.slice(0, 5).join(', ')}`,
      explanation:
        'The URL path or subdomain contains keywords commonly associated with authentication portals, account verification, or credential updates. When combined with suspicious hosts or generic TLDs, this strongly points to social engineering traps.',
    })
    recommendations.push(
      'Verify the domain name carefully before submitting any authentication credentials.'
    )
  }

  // -------------------------------------------------------------
  // Rule 13: High-Abuse / Disposable TLD
  // -------------------------------------------------------------
  if (HIGH_ABUSE_TLDS.has(tld)) {
    const scoreImpact = 15
    rawScore += scoreImpact
    threatTags.add('High-Abuse TLD')
    findings.push({
      rule_id: 'HEUR_SUSPICIOUS_TLD',
      title: `Elevated Risk Top-Level Domain (.${tld})`,
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `Domain utilizes top-level domain '.${tld}'`,
      explanation: `The top-level domain '.${tld}' has historically shown a disproportionately high incidence of disposable phishing and scam operations due to low registration pricing and permissive verification policies.`,
    })
  }

  // -------------------------------------------------------------
  // Rule 14: High Shannon Entropy in Hostname (DGA / Obfuscation)
  // -------------------------------------------------------------
  if (mainLabel.length > 10 && labelEntropy > 3.6) {
    const scoreImpact = 15
    rawScore += scoreImpact
    threatTags.add('DGA / High Entropy')
    findings.push({
      rule_id: 'HEUR_HIGH_ENTROPY_HOST',
      title: 'High Lexical Entropy in Domain Label',
      severity: 'medium',
      score_impact: scoreImpact,
      evidence: `Label '${mainLabel}' Shannon entropy is ${labelEntropy.toFixed(2)} bits (randomness threshold > 3.6)`,
      explanation:
        'The domain name label displays elevated randomness and character entropy. This pattern is characteristic of Algorithmically Generated Domains (DGA) or automated disposable campaign infrastructure.',
    })
  }

  // -------------------------------------------------------------
  // Rule 15: Dangerous File Extension in Path
  // -------------------------------------------------------------
  for (const ext of MALICIOUS_EXTENSIONS) {
    if (
      pathname.toLowerCase().endsWith(ext) ||
      fullPath.toLowerCase().includes(ext + '?') ||
      fullPath.toLowerCase().includes(ext + '&')
    ) {
      const scoreImpact = 30
      rawScore += scoreImpact
      threatTags.add('Executable Payload')
      findings.push({
        rule_id: 'HEUR_EXECUTABLE_DOWNLOAD',
        title: `Direct Executable / Payload Extension (${ext})`,
        severity: 'high',
        score_impact: scoreImpact,
        evidence: `Target path ends with high-risk executable extension '${ext}'`,
        explanation: `The link points directly to a file with the dangerous extension '${ext}'. Clicking this URL is likely to initiate an automated binary payload download, risking malicious code execution.`,
      })
      recommendations.push(
        'Do not download or execute files from this link. It appears to serve an executable payload.'
      )
      break
    }
  }

  // -------------------------------------------------------------
  // Final Score & Risk Categorization
  // -------------------------------------------------------------
  const heuristicScore = Math.min(100, Math.max(0, rawScore))
  let riskCategory: 'Low' | 'Medium' | 'High'
  let scoreDescription: string
  let summary: string

  if (heuristicScore >= 66) {
    riskCategory = 'High'
    scoreDescription = 'High Heuristic Risk — Multiple Phishing / Threat Indicators'
    summary =
      'The analyzed URL presents multiple severe red flags typically seen in credential phishing, brand spoofing, or malicious payload delivery campaigns.'
  } else if (heuristicScore >= 26) {
    riskCategory = 'Medium'
    scoreDescription = 'Medium Heuristic Risk — Suspicious Characteristics Detected'
    summary =
      'The URL exhibits notable anomalies or obfuscated patterns. Exercise caution and verify the source before interacting or providing any sensitive information.'
  } else {
    riskCategory = 'Low'
    scoreDescription = 'Low Heuristic Risk — No Obvious Static Red Flags'
    summary =
      'Static heuristic analysis did not detect overt deceptive patterns or malicious hallmarks. However, newly registered or targeted phishing sites can evade static rules.'
  }

  if (recommendations.length === 0) {
    if (riskCategory === 'Low') {
      recommendations.push(
        "Confirm the sender's identity through an out-of-band communication channel before sharing credentials."
      )
      recommendations.push(
        'Verify that the destination domain matches the official organization website.'
      )
    } else {
      recommendations.push('Do not submit credentials or personal information on this page.')
    }
  }

  const disclaimer =
    'Disclaimer: Heuristic analysis assesses structural and lexical characteristics without opening or visiting the target destination. It provides risk indicators but CANNOT guarantee that a URL is safe. Absence of suspicious indicators does not prove safety; always exercise caution with untrusted links.'

  const components: ComponentBreakdown = {
    scheme,
    username: parsed.username || undefined,
    password: parsed.password || undefined,
    subdomains,
    registered_domain: registeredDomain,
    tld,
    port: parsed.port || undefined,
    path: pathname,
    query_params: queryParams,
    hash,
    is_ip: isIp,
    entropy: Number(labelEntropy.toFixed(2)),
  }

  return {
    submitted_url: originalUrl,
    normalized_url: parsed.href,
    scheme,
    hostname: rawHostname,
    registered_domain: registeredDomain,
    path: pathname,
    risk_category: riskCategory,
    heuristic_score: heuristicScore,
    score_description: scoreDescription,
    summary,
    findings_count: findings.length,
    findings,
    recommendations,
    disclaimer,
    analyzed_at: new Date().toISOString(),
    passive_analysis: true,
    threat_tags: Array.from(threatTags),
    components,
    defanged_url: defangUrl(originalUrl),
  }
}
