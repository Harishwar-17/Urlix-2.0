import ipaddress
import math
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Common brand identifiers frequently spoofed in phishing attacks
WELL_KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "meta": ["meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dropbox": ["dropbox.com"],
    "yahoo": ["yahoo.com"],
    "linkedin": ["linkedin.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "adobe": ["adobe.com"],
}

# Known public URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "t.co",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "soo.gd",
    "s.id",
    "t.ly",
    "v.gd",
    "tiny.cc",
    "bl.ink",
}

# TLDs historically characterized by high abuse ratios in disposable campaigns
HIGH_ABUSE_TLDS = {
    "top", "xyz", "club", "work", "click", "buzz", "surf",
    "monster", "fit", "rest", "tk", "ml", "ga", "cf", "gq",
    "gdn", "stream", "cam", "kim", "country"
}

# Sensitive credential / transaction keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "banking", "security", "update", "wallet", "confirm",
    "confirmation", "password", "support", "billing", "authenticate",
    "recover", "secure-login", "auth", "credential"
]

# High-risk file extensions in path
MALICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".jar",
    ".iso", ".img", ".dll", ".pif"
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_ip_address(hostname: str) -> bool:
    """Safely checks if hostname is a valid IPv4 or IPv6 address."""
    clean_host = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def extract_domain_parts(hostname: str) -> Tuple[str, str, List[str]]:
    """
    Extracts registered domain, TLD, and subdomain list from hostname.
    Handles standard dots cleanly without external C-bindings.
    """
    hostname = hostname.lower().strip()
    parts = hostname.split(".")
    if len(parts) <= 1:
        return hostname, "", []
    
    tld = parts[-1]
    # Handle simple 2-part ccTLDs like .co.uk, .com.br, etc.
    if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "net", "gov", "edu"] and len(parts[-1]) == 2:
        registered_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-3]
    else:
        registered_domain = f"{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-2]

    return registered_domain, tld, subdomains

def validate_url_syntax(raw_url: str) -> Tuple[bool, str, Optional[urllib.parse.ParseResult]]:
    """
    Validates URL syntax strictly:
    - Must be non-empty string.
    - Must have http or https scheme.
    - Hostname must be present and valid.
    - Never triggers network lookups or fetches.
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "Input must be a non-empty string.", None

    url_str = raw_url.strip()
    if len(url_str) > 2048:
        return False, "URL exceeds maximum permitted length of 2048 characters.", None

    # Check for forbidden dangerous pseudo-schemes
    forbidden_schemes = ("javascript:", "data:", "file:", "vbscript:", "about:")
    if any(url_str.lower().startswith(s) for s in forbidden_schemes):
        return False, "Scheme not supported. Only HTTP and HTTPS URLs are accepted for analysis.", None

    # Default to http:// if no scheme is provided for parsing convenience
    if not (url_str.lower().startswith("http://") or url_str.lower().startswith("https://")):
        # If scheme is present but unsupported (e.g. ftp://, ssh://)
        if "://" in url_str:
            scheme = url_str.split("://")[0].lower()
            return False, f"Unsupported URL scheme '{scheme}'. Only http and https are analyzed.", None
        url_str = "http://" + url_str

    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}'. Only http and https URLs are accepted.", None

    if not parsed.netloc:
        return False, "URL authority/host component is missing.", None

    # Check hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Unable to extract a valid hostname from the URL.", None

    return True, "", parsed

class URLExplainableAnalyzer:
    """
    URLIX Explainable Heuristic Detection Engine.
    Executes purely passive lexical and structural inspection.
    """

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        valid, err_msg, parsed = validate_url_syntax(raw_url)
        if not valid or not parsed:
            raise ValueError(err_msg)

        original_url = raw_url.strip()
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        full_path = path + ("?" + query if query else "")

        findings: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        raw_score = 0

        reg_domain, tld, subdomains = extract_domain_parts(hostname)

        # -------------------------------------------------------------
        # Rule 1: HTTP vs HTTPS Transport Encryption
        # -------------------------------------------------------------
        if scheme == "http":
            score_impact = 15
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_UNENCRYPTED_HTTP",
                "title": "Unencrypted HTTP Scheme",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"Protocol scheme is '{scheme}://'",
                "explanation": (
                    "The URL communicates over unencrypted plaintext HTTP. Modern legitimate sites—particularly "
                    "those with login or financial interactions—mandate HTTPS encryption. While not all HTTP links "
                    "are malicious, attackers frequently leverage plain HTTP for transient landing pages."
                )
            })
            recommendations.append(
                "Never enter passwords, tokens, or financial data on an unencrypted HTTP link."
            )
        else:
            findings.append({
                "rule_id": "HEUR_HTTPS_PRESENT",
                "title": "HTTPS Transport Protocol Detected",
                "severity": "info",
                "score_impact": 0,
                "evidence": "Protocol scheme is 'https://'",
                "explanation": (
                    "The link utilizes HTTPS encryption for transport security. Note that modern phishing sites "
                    "routinely obtain free SSL/TLS certificates, so HTTPS alone does not prove the website is safe."
                )
            })

        # -------------------------------------------------------------
        # Rule 2: IP Address in Hostname
        # -------------------------------------------------------------
        if is_ip_address(hostname):
            score_impact = 35
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_RAW_IP_HOST",
                "title": "Direct IP Address Hostname",
                "severity": "high",
                "score_impact": score_impact,
                "evidence": f"Hostname is an explicit IP literal: {hostname}",
                "explanation": (
                    "The URL directs to a raw numerical IP address instead of a registered domain name. "
                    "Legitimate commercial organizations almost universally brand through domain names. Attackers "
                    "frequently use direct IP addresses to evade domain-based reputation filters and blocklists."
                )
            })
            recommendations.append(
                "Avoid interacting with links hosted directly on raw IP addresses unless connecting to verified internal servers."
            )

        # -------------------------------------------------------------
        # Rule 3: Misleading Authority Credentials (@ in URL)
        # -------------------------------------------------------------
        if "@" in netloc or "@" in raw_url.split("/")[2]:
            score_impact = 40
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_USERINFO_TRICK",
                "title": "Misleading '@' Authority Obfuscation",
                "severity": "high",
                "score_impact": score_impact,
                "evidence": "Contains '@' delimiter within authority component",
                "explanation": (
                    "According to RFC 3986, characters preceding the '@' in the authority component denote userinfo, "
                    "while modern browsers ignore them and connect exclusively to the server specified AFTER the '@'. "
                    "This is an adversarial deception tactic used to mimic trusted brands (e.g., 'https://paypal.com@malicious.com')."
                )
            })
            recommendations.append(
                "Treat any URL containing an '@' in the domain component as hostile deception."
            )

        # -------------------------------------------------------------
        # Rule 4: Punycode / Internationalized Domain Name (Homograph Attack)
        # -------------------------------------------------------------
        if "xn--" in hostname:
            score_impact = 30
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_PUNYCODE_HOMOGRAPH",
                "title": "Punycode IDN Homograph Pattern",
                "severity": "high",
                "score_impact": score_impact,
                "evidence": f"Punycode identifier 'xn--' found in domain: {hostname}",
                "explanation": (
                    "Punycode translates Unicode Internationalized Domain Names (IDNs) into ASCII. "
                    "Adversaries utilize visually identical characters (homoglyphs from Cyrillic or Greek alphabets) "
                    "to construct deceptive replicas of well-known domain names."
                )
            })
            recommendations.append(
                "Inspect the true Unicode rendering of this Punycode domain before trusting its authenticity."
            )

        # -------------------------------------------------------------
        # Rule 5: Excessively Long URL and Components
        # -------------------------------------------------------------
        url_len = len(raw_url)
        if url_len > 120:
            score_impact = 15
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_EXCESSIVE_URL_LENGTH",
                "title": "Unusually Long URL Length",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"URL length is {url_len} characters (standard baseline < 75 chars)",
                "explanation": (
                    "Excessively long URLs are often engineered to obscure the true domain name in narrow mobile "
                    "address bars, embed serialized exploit payloads, or bypass standard signature scanners."
                )
            })
        elif url_len > 75:
            score_impact = 8
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_ELEVATED_URL_LENGTH",
                "title": "Elevated URL Length",
                "severity": "low",
                "score_impact": score_impact,
                "evidence": f"URL length is {url_len} characters",
                "explanation": (
                    "The URL is longer than typical website links. While common for complex web applications and tracking "
                    "parameters, elevated length warrants scrutiny."
                )
            })

        # -------------------------------------------------------------
        # Rule 6: Excessive Subdomain Depth
        # -------------------------------------------------------------
        if len(subdomains) >= 3:
            score_impact = 20
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_EXCESSIVE_SUBDOMAINS",
                "title": "Excessive Subdomain Hierarchy",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"{len(subdomains)} subdomain layers detected: {'.'.join(subdomains)}",
                "explanation": (
                    "Deep subdomain hierarchies (3 or more levels) are common when attackers use free dynamic DNS services "
                    "or compromised subdomains to simulate legitimate organizations while masking the real root domain."
                )
            })
            recommendations.append(
                f"Verify whether the actual root domain '{reg_domain}' is legitimately affiliated with the service."
            )

        # -------------------------------------------------------------
        # Rule 7: Known URL Shortener
        # -------------------------------------------------------------
        if hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + s) for s in SHORTENER_DOMAINS):
            score_impact = 18
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_URL_SHORTENER",
                "title": "Obfuscated URL Shortening Service",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"Host '{hostname}' matches known public shortener service",
                "explanation": (
                    "URL shortening hides the actual target destination. Attackers frequently use shorteners in SMS/phishing "
                    "campaigns to bypass automated security gateways and deceive users about the destination host."
                )
            })
            recommendations.append(
                "Do not click shortened links directly without first previewing the expanded destination."
            )

        # -------------------------------------------------------------
        # Rule 8: Brand Spoofing / Impersonation Heuristics
        # -------------------------------------------------------------
        detected_brand_target: Optional[str] = None
                # Detect trusted brand names in URL userinfo before '@'
        userinfo = netloc.rsplit("@", 1)[0] if "@" in netloc else ""

        if userinfo:
            userinfo_lower = userinfo.lower()

            for brand, legitimate_domains in WELL_KNOWN_BRANDS.items():
                if any(domain in userinfo_lower for domain in legitimate_domains):
                    actual_host_is_legitimate = any(
                        hostname == domain or hostname.endswith("." + domain)
                        for domain in legitimate_domains
                    )

                    if not actual_host_is_legitimate:
                        score_impact = 25
                        raw_score += score_impact

                        findings.append({
                            "rule_id": "HEUR_BRAND_IN_USERINFO",
                            "title": f"Potential {brand.capitalize()} Brand Deception",
                            "severity": "high",
                            "score_impact": score_impact,
                            "evidence": (
                                f"Brand-like text appears before '@', but the actual hostname "
                                f"is '{hostname}'"
                            ),
                            "explanation": (
                                "The URL places a trusted brand name before '@'. "
                                "The actual destination is the hostname after '@', "
                                "which does not belong to that brand's listed official domains."
                            )
                        })

                        recommendations.append(
                            f"If this link claims to be from {brand.capitalize()}, "
                            "do not log in. Navigate to the official website directly."
                        )
                        break
        for brand, legitimate_domains in WELL_KNOWN_BRANDS.items():
            # Check if brand appears as token in hostname
            host_tokens = re.split(r"[-._]", hostname)
            if brand in host_tokens:
                # If the domain is NOT in the official legitimate domain whitelist
                is_legit = any(hostname == ld or hostname.endswith("." + ld) for ld in legitimate_domains)
                if not is_legit:
                    detected_brand_target = brand
                    score_impact = 35
                    raw_score += score_impact
                    findings.append({
                        "rule_id": "HEUR_BRAND_IMPERSONATION",
                        "title": f"Potential Brand Impersonation ({brand.capitalize()})",
                        "severity": "high",
                        "score_impact": score_impact,
                        "evidence": (
                            f"Host '{hostname}' includes brand name '{brand}', but registered domain is '{reg_domain}' "
                            f"(expected official domain: {', '.join(legitimate_domains)})"
                        ),
                        "explanation": (
                            f"The URL references the '{brand.capitalize()}' trademark within its hostname or subdomains, "
                            f"yet resolves to an unrelated registered domain ('{reg_domain}'). This is a primary indicator of "
                            "phishing sites designed to harvest user account credentials."
                        )
                    })
                    recommendations.append(
                        f"If this link claims to be from {brand.capitalize()}, DO NOT log in. Navigate directly to the official website instead."
                    )
                    break

        # -------------------------------------------------------------
        # Rule 9: Phishing Keywords in Path or Subdomains
        # -------------------------------------------------------------
        found_keywords: List[str] = []
        for kw in SUSPICIOUS_KEYWORDS:
            # Check path and subdomains
            subdomain_str = ".".join(subdomains).lower()
            if kw in full_path.lower() or kw in subdomain_str:
                found_keywords.append(kw)

        if found_keywords:
            # Higher impact if combined with brand spoofing, http, or non-brand domains
            base_kw_impact = min(25, len(found_keywords) * 8)
            raw_score += base_kw_impact
            findings.append({
                "rule_id": "HEUR_CREDENTIAL_KEYWORDS",
                "title": "Authentication / Credential Harvesting Keywords",
                "severity": "medium" if base_kw_impact < 20 else "high",
                "score_impact": base_kw_impact,
                "evidence": f"Sensitive keywords detected: {', '.join(found_keywords[:5])}",
                "explanation": (
                    "The URL path or subdomain contains keywords commonly associated with authentication portals, "
                    "account verification, or credential updates. When combined with suspicious hosts or generic TLDs, "
                    "this strongly points to social engineering traps."
                )
            })
            recommendations.append(
                "Verify the domain name carefully before submitting any authentication credentials."
            )

        # -------------------------------------------------------------
        # Rule 10: High-Abuse / Disposable TLD
        # -------------------------------------------------------------
        if tld in HIGH_ABUSE_TLDS:
            score_impact = 15
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_SUSPICIOUS_TLD",
                "title": f"Elevated Risk Top-Level Domain (.{tld})",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"Domain utilizes top-level domain '.{tld}'",
                "explanation": (
                    f"The top-level domain '.{tld}' has historically shown a disproportionately high incidence of disposable "
                    "phishing and scam operations due to low registration pricing and permissive verification policies."
                )
            })

        # -------------------------------------------------------------
        # Rule 11: High Shannon Entropy in Hostname (DGA / Obfuscation)
        # -------------------------------------------------------------
        main_label = subdomains[0] if subdomains else reg_domain.split(".")[0]
        label_entropy = calculate_shannon_entropy(main_label)
        if len(main_label) > 10 and label_entropy > 3.6:
            score_impact = 15
            raw_score += score_impact
            findings.append({
                "rule_id": "HEUR_HIGH_ENTROPY_HOST",
                "title": "High Lexical Entropy in Domain Label",
                "severity": "medium",
                "score_impact": score_impact,
                "evidence": f"Label '{main_label}' Shannon entropy is {label_entropy:.2f} bits (randomness threshold > 3.6)",
                "explanation": (
                    "The domain name label displays elevated randomness and character entropy. This pattern is characteristic "
                    "of Algorithmically Generated Domains (DGA) or automated disposable campaign infrastructure."
                )
            })

        # -------------------------------------------------------------
        # Rule 12: Dangerous File Extension in Path
        # -------------------------------------------------------------
        for ext in MALICIOUS_EXTENSIONS:
            if path.lower().endswith(ext) or (ext + "?") in path.lower() or (ext + "&") in path.lower():
                score_impact = 30
                raw_score += score_impact
                findings.append({
                    "rule_id": "HEUR_EXECUTABLE_DOWNLOAD",
                    "title": f"Direct Executable / Payload Extension ({ext})",
                    "severity": "high",
                    "score_impact": score_impact,
                    "evidence": f"Target path ends with high-risk executable extension '{ext}'",
                    "explanation": (
                        f"The link points directly to a file with the dangerous extension '{ext}'. Clicking this URL is "
                        "likely to initiate an automated binary payload download, risking malicious code execution."
                    )
                })
                recommendations.append(
                    "Do not download or execute files from this link. It appears to serve an executable payload."
                )
                break

        # -------------------------------------------------------------
        # Final Score & Risk Categorization
        # -------------------------------------------------------------
        heuristic_score = min(100, max(0, raw_score))

        if heuristic_score >= 66:
            risk_category = "High"
            score_description = "High Heuristic Risk — Multiple Phishing / Threat Indicators"
            summary = (
                "The analyzed URL presents multiple severe red flags typically seen in credential phishing, "
                "brand spoofing, or malicious payload delivery campaigns."
            )
        elif heuristic_score >= 26:
            risk_category = "Medium"
            score_description = "Medium Heuristic Risk — Suspicious Characteristics Detected"
            summary = (
                "The URL exhibits notable anomalies or obfuscated patterns. Exercise caution and verify the source "
                "before interacting or providing any sensitive information."
            )
        else:
            risk_category = "Low"
            score_description = "Low Heuristic Risk — No Obvious Static Red Flags"
            summary = (
                "Static heuristic analysis did not detect overt deceptive patterns or malicious hallmarks. "
                "However, newly registered or targeted phishing sites can evade static rules."
            )

        # Baseline recommendations if list is empty
        if not recommendations:
            if risk_category == "Low":
                recommendations.append(
                    "Confirm the sender's identity through an out-of-band communication channel before sharing credentials."
                )
                recommendations.append(
                    "Verify that the destination domain matches the official organization website."
                )
            else:
                recommendations.append(
                    "Do not submit credentials or personal information on this page."
                )

        disclaimer = (
            "Disclaimer: Heuristic analysis assesses structural and lexical characteristics without opening or "
            "visiting the target destination. It provides risk indicators but CANNOT guarantee that a URL is safe. "
            "Absence of suspicious indicators does not prove safety; always exercise caution with untrusted links."
        )

        return {
            "submitted_url": raw_url,
            "normalized_url": parsed.geturl(),
            "scheme": scheme,
            "hostname": hostname,
            "registered_domain": reg_domain,
            "path": path,
            "risk_category": risk_category,
            "heuristic_score": heuristic_score,
            "score_description": score_description,
            "summary": summary,
            "findings_count": len(findings),
            "findings": findings,
            "recommendations": recommendations,
            "disclaimer": disclaimer,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "passive_analysis": True,
        }

# Singleton analyzer instance
analyzer = URLExplainableAnalyzer()
