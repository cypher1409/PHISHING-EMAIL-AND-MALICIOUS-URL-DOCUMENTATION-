# PHISHING-EMAIL-AND-MALICIOUS-URL-DOCUMENTATION-
# Phishing Investigation: Credential Harvesting & URL Analysis

## 🚩 Project Overview
- **Project Title:** Phishing Email Content & URL Investigation Lab
- **Difficulty Level:** Beginner → Light Intermediate
- **Objective:** Analyze a phishing email to identify malicious URLs, assess threat levels using industry-standard tools, and provide mitigation recommendations.

### 📝 Scenario Summary
In this simulation, **NexShield**, a cybersecurity consulting firm, was targeted by a phishing campaign aimed at administrative staff. The attackers utilized "Living off the Cloud" techniques—hosting a credential harvesting page on a legitimate platform (**Vercel**) and obfuscating the URL to bypass traditional security filters. As a Junior Security Analyst, I investigated the email’s validity, performed a deep dive into the URL’s reputation, and documented the risk to the organization.

---

## 🛠 Investigation Methodology

### Step 1: Email Content Analysis
I performed a manual inspection of the email body to identify psychological triggers and technical inconsistencies.
* **Phishing Red Flags:** * Generic salutations ("Dear Admin").
    * Artificial urgency (24-hour deadline).
    * Suspicious call-to-action (verify access via an external link).
* **Social Engineering:** The campaign leveraged **Urgency** and **Fear** (potential account suspension) to bypass critical thinking.

### Step 2: URL Reconstruction
The link provided was intentionally mangled: `app/.securesupport.vercel.https://`
* **Corrected URL:** `https://securesupport.vercel.app/`
* **Analyst Note:** Attackers obfuscate URLs to evade **Secure Email Gateways (SEGs)**. By breaking the standard URI structure, they prevent automated scanners from blacklisting the link during transit.

### Step 3: Threat Intelligence Analysis
I utilized a multi-engine approach to verify the threat:
* **VirusTotal:** Confirmed a high detection ratio for **Phishing** and **Malicious** content.
* **Urlscan.io:** A sandbox execution revealed a landing page mimicking a corporate login portal designed for data exfiltration.
* **Cisco Talos:** Identified the domain reputation as "Poor" and flagged it as a known source of spam/phishing traffic.

### Step 4: WHOIS Investigation
* **Base Domain:** `vercel.app`
* **Registrar:** Tucows Domain Inc.
* **Anomalies:** While the base domain is a legitimate hosting provider, the **subdomain** `securesupport` was identified as a rogue instance created specifically for this campaign to inherit the "trusted" reputation of the parent domain.

---

## 🛡 Indicators of Compromise (IOCs)
| Type | Value |
| :--- | :--- |
| **Malicious URL** | `https://securesupport.vercel.app/` |
| **Hosting Platform** | Vercel (Cloud App) |
| **Subject Line** | "Urgent: Verify Admin Access Required" |
| **Technique** | Credential Harvesting / Subdomain Squatting |

---

## ⚠️ Risk Assessment
If an administrative employee submits credentials:
1.  **Administrative Compromise:** Direct loss of high-privilege account control.
2.  **Lateral Movement:** Attackers could use the session to access internal consulting databases.
3.  **Data Exfiltration:** Sensitive client data held by NexShield could be leaked, leading to legal and financial liability.

---

## 💡 Mitigation & Recommendations

### Immediate Actions
* **DNS/Firewall Block:** Immediately blacklist the `securesupport.vercel.app` subdomain.
* **Credential Revocation:** Force a password reset for any staff who interacted with the link.
* **MFA Enforcement:** Ensure hardware or app-based MFA is mandatory for all admin accounts.

### Long-Term Strategy
* **Advanced Email Filtering:** Implement a gateway that flags "Look-alike" subdomains from cloud providers.
* **Security Awareness:** Conduct quarterly phishing simulations focusing on "Living off the Cloud" tactics.
* **SIEM Tuning:** Create alerts for logins originating from newly observed subdomains on public hosting platforms.

---

## 🎓 Lessons Learned
* **Tool Proficiency:** Gained hands-on experience with VirusTotal, Urlscan.io, and Cisco Talos.
* **De-obfuscation:** Learned techniques for safely reconstructing and "defanging" malicious links.
* **Cloud Threats:** Developed an understanding of how attackers abuse trusted cloud providers (Vercel, Netlify) to bypass filters.
*
