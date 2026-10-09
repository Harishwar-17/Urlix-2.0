import json
import urllib.request
import urllib.error

test_matrix = [
    ("Valid Ordinary HTTPS", "https://github.com/explore", 200, "Low"),
    ("Valid Ordinary HTTP", "http://example.com/page", 200, "Low"),
    ("IP-based Host URL", "http://192.168.1.1/login", 200, "High"),
    ("Misleading @ Authority URL", "https://apple.com@evil-phishing.top/verify", 200, "High"),
    ("Brand Spoofing & Subdomains", "http://login.microsoft.com.secure-auth-update.xyz/auth.php", 200, "High"),
    ("Excessively Long URL", "https://suspicious-domain-tracking.com/" + "token/" * 25 + "verify-account", 200, "Medium"),
    ("Punycode Homograph URL", "http://xn--pple-43d.com/store", 200, "Medium"),
    ("URL Shortener", "https://bit.ly/3xSampleShortener", 200, "Low"),
    ("Malformed / Unsupported Scheme", "ftp://malicious-ftp.com/payload", 400, None),
    ("Dangerous Scheme", "javascript:alert(1)", 400, None),
    ("Empty URL Input", "", 400, None),
]

print("=== AUTOMATED ENDPOINT VERIFICATION (Backend & Vite Proxy) ===")
all_passed = True
for label, url, expected_status, expected_risk in test_matrix:
    for target in [
        "http://127.0.0.1:8000/api/analyze",
        "http://[::1]:5176/api/analyze",
    ]:
        port_label = "Backend :8000" if "8000" in target else "Vite Proxy :5176"
        data = json.dumps({"url": url}).encode()
        req = urllib.request.Request(
            target,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                body = json.loads(resp.read().decode())
                risk = body.get("risk_category")
                score = body.get("heuristic_score")
                findings = body.get("findings_count")

                if status == expected_status and (
                    expected_risk is None or risk == expected_risk
                ):
                    print(
                        f"[PASS] {label} -> {port_label}: HTTP {status}, "
                        f"Category: {risk}, Score: {score}/100, Findings: {findings}"
                    )
                else:
                    all_passed = False
                    print(
                        f"[WARN] {label} -> {port_label}: HTTP {status}, "
                        f"Got Risk: {risk} (expected {expected_risk})"
                    )

        except urllib.error.HTTPError as err:
            err_body = err.read().decode()
            if err.code == expected_status:
                print(
                    f"[PASS] {label} -> {port_label}: HTTP {err.code} "
                    f"(Expected): {err_body[:60]}..."
                )
            else:
                all_passed = False
                print(
                    f"[FAIL] {label} -> {port_label}: "
                    f"Expected {expected_status}, got {err.code}"
                )

        except Exception as e:
            all_passed = False
            print(f"[FAIL] {label} -> {port_label}: Exception: {e}")