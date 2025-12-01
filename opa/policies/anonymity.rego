package anonymity

import rego.v1

allow := true

suggested_backend := backend if {
    backend := determine_backend_by_risk
}

# Risk score - FORCE HIGH for malicious domains
risk_score := 0.95 if {
    analyze_website_risk >= 0.9
} else := score if {
    website_risk := analyze_website_risk
    url_risk := analyze_url_patterns
    domain_risk := check_domain_reputation
    score := (website_risk * 0.4) + (url_risk * 0.5) + (domain_risk * 0.1)
}

risk_level := "low" if {
    risk_score < 0.3
} else := "medium" if {
    risk_score >= 0.3; risk_score < 0.6
} else := "high"

reason := "Safe website detected - Using fast direct connection" if {
    risk_level == "low"
} else := sprintf("Suspicious patterns detected (risk: %.2f) - Using Tor for protection", [risk_score]) if {
    risk_level == "medium"
} else := sprintf("High-risk detected (risk: %.2f) - Using Tor for maximum safety", [risk_score])

determine_backend_by_risk := "direct" if {
    risk_level == "low"
} else := "tor"

# WEBSITE RISK - FIXED VERSION using contains for domain matching
is_safe_domain if {
    some safe_domain in data.safe_domains
    contains(lower(input.request.target_url), lower(safe_domain))
}

is_malicious_domain if {
    some malicious_domain in data.malicious_domains
    contains(lower(input.request.target_url), lower(malicious_domain))
}

analyze_website_risk := 0.1 if {
    is_safe_domain
    not is_malicious_domain
} else := 1.0 if {
    is_malicious_domain
} else := 0.5

analyze_url_patterns := risk if {
    ip_risk := check_ip_address
    private_ip_risk := check_private_ip
    typo_risk := check_typosquatting
    keyword_risk := check_suspicious_keywords
    tld_risk := check_suspicious_tld
    risk := (ip_risk * 2 + private_ip_risk * 2 + typo_risk + keyword_risk + tld_risk) / 6
}

check_ip_address := 1.0 if {
    regex.match(`(?i)^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, input.request.target_url)
} else := 0.0

check_private_ip := 1.0 if {
    regex.match(`(?i)192\.168\.\d{1,3}\.\d{1,3}`, input.request.target_url)
} else := 1.0 if {
    regex.match(`(?i)10\.\d{1,3}\.\d{1,3}\.\d{1,3}`, input.request.target_url)
} else := 1.0 if {
    regex.match(`(?i)172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}`, input.request.target_url)
} else := 0.0

check_typosquatting := 0.9 if {
    regex.match(`(?i)paypa1`, input.request.target_url)
} else := 0.9 if {
    regex.match(`(?i)amaz0n`, input.request.target_url)
} else := 0.0

check_suspicious_keywords := 0.8 if {
    regex.match(`(?i).*login.*verify.*secure.*`, input.request.target_url)
} else := 0.7 if {
    regex.match(`(?i).*urgent.*account.*`, input.request.target_url)
} else := 0.0

check_suspicious_tld := 0.7 if {
    contains(input.request.target_url, ".xyz")
} else := 0.7 if {
    contains(input.request.target_url, ".tk")
} else := 0.7 if {
    contains(input.request.target_url, ".ml")
} else := 0.7 if {
    contains(input.request.target_url, ".ru")
} else := 0.0

check_domain_reputation := 0.1 if {
    startswith(input.request.target_url, "https://")
} else := 0.4

use_fingerprint_protection := true

privacy_level := "basic" if {
    risk_level == "low"
} else := "moderate" if {
    risk_level == "medium"
} else := "maximum"
