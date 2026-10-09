import json
import analyzer

def run_tests():
    a = analyzer.URLExplainableAnalyzer()
    test_urls = [
        ("https://google.com", "Ordinary benign HTTPS"),
        ("https://github.com/explore", "Legitimate deep path"),
        ("http://insecure-personal-blog.org/about", "Plain HTTP benign"),
        ("http://192.168.1.100/login/update", "Raw IP with login keywords and HTTP"),
        ("https://paypal.com@evil-phish.top/account-verify", "Misleading @ and suspicious TLD"),
        ("http://login.microsoft.com.secure-auth-update.xyz/auth.php", "Brand impersonation, multi-subdomains, .xyz, keywords"),
        ("https://bit.ly/3xSampleShortener", "Known URL shortener"),
        ("http://xn--pple-43d.com/store", "Punycode IDN homograph"),
        ("https://bankofamerica-secure-login-update-verify-billing-portal.com/account/security/update-password.exe", "Direct executable + excessive length + brand keyword spoofing"),
        ("ftp://malicious.com/file", "Unsupported FTP scheme"),
        ("javascript:alert(1)", "Forbidden javascript pseudo-scheme"),
        ("", "Empty URL input"),
    ]

    print("=== URLIX ENGINE TEST SUITE ===")
    for u, description in test_urls:
        print(f"\n[TEST CASE] {description}")
        print(f"Target: '{u}'")
        try:
            res = a.analyze(u)
            print(f"Result: Risk Category = {res['risk_category']}, Heuristic Score = {res['heuristic_score']}/100")
            print(f"Findings ({len(res['findings'])}):")
            for f in res['findings']:
                print(f"  - [{f['severity'].upper()}] {f['title']} (+{f['score_impact']}): {f['evidence']}")
            print(f"Recommendations ({len(res['recommendations'])}):")
            for r in res['recommendations']:
                print(f"  * {r}")
        except ValueError as e:
            print(f"Safely Rejected as Expected: {e}")

if __name__ == "__main__":
    run_tests()
