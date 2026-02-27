# PHISHING-EMAIL-AND-MALICIOUS-URL-DOCUMENTATION-
# Phishing Investigation: Credential Harvesting & URL Analysis

## 🚩 Project Overview
- **[span_2](start_span)Project Title:** Phishing Email Content & URL Investigation Lab[span_2](end_span)
- **Difficulty Level:** Beginner → Light Intermediate
- **[span_3](start_span)Objective:** Analyze a phishing email to identify malicious URLs, assess threat levels using industry-standard tools, and provide mitigation recommendations[span_3](end_span).

### 📝 Scenario Summary
[span_4](start_span)In this simulation, **NexShield**, a cybersecurity consulting firm, was targeted by a phishing campaign aimed at administrative staff[span_4](end_span). [span_5](start_span)[span_6](start_span)The attackers utilized "Living off the Cloud" techniques—hosting a credential harvesting page on a legitimate platform (**Vercel**) and obfuscating the URL to bypass traditional security filters[span_5](end_span)[span_6](end_span). [span_7](start_span)As a Junior Security Analyst, I investigated the email’s validity, performed a deep dive into the URL’s reputation, and documented the risk to the organization[span_7](end_span).

---

## 🛠 Investigation Methodology

### Step 1: Email Content Analysis
[span_8](start_span)I performed a manual inspection of the email body to identify psychological triggers and technical inconsistencies[span_8](end_span).
* **[span_9](start_span)Phishing Red Flags:** * Generic salutations ("Dear Admin")[span_9](end_span).
    * [span_10](start_span)Artificial urgency ("verify access immediately")[span_10](end_span).
    * [span_11](start_span)Mismatched Display Name vs. Sender Address[span_11](end_span).
    * [span_12](start_span)Unusual Call to Action: Manual login via an email link[span_12](end_span).
* **[span_13](start_span)Social Engineering:** The campaign leveraged **Urgency**, **Authority**, and **Fear** (potential account suspension) to bypass critical thinking[span_13](end_span).

### Step 2: URL Reconstruction
[span_14](start_span)The link provided was intentionally mangled: `app/.securesupport.vercel.https://`[span_14](end_span)
* **[span_15](start_span)Corrected URL:** `https://securesupport.vercel.app/`[span_15](end_span)
* **[span_16](start_span)Analyst Note:** Attackers obfuscate URLs to evade **Secure Email Gateways (SEGs)**[span_16](end_span). [span_17](start_span)By breaking the standard URI structure, they prevent automated scanners from blacklisting the link during transit[span_17](end_span).

### Step 3: Threat Intelligence Analysis
I utilized a multi-engine approach to verify the threat:

#### VirusTotal Analysis
[span_18](start_span)Confirmed a high detection ratio (17/94) for **Phishing** and **Malicious** content[span_18](end_span).
![VirusTotal Detection](images/virustotal.jpg)

#### Urlscan.io Sandbox
[span_19](start_span)Revealed a landing page mimicking a corporate login portal designed for data exfiltration[span_19](end_span).
![Urlscan Landing Page](images/urlscan.jpg)

#### Cisco Talos
[span_20](start_span)Identified the domain as "Untrusted" and flagged it as a known source of malicious exploits[span_20](end_span).
![Cisco Talos Reputation](images/talos.jpg)

### Step 4: WHOIS Investigation
* **[span_21](start_span)Base Domain:** `vercel.app`[span_21](end_span)
* **[span_22](start_span)Registrar:** Tucows Domains Inc[span_22](end_span)
* **[span_23](start_span)Anomalies:** While the base domain is legitimate, the **subdomain** `securesupport` was created to inherit the trusted reputation of the parent domain[span_23](end_span).
![WHOIS Details](images/whois.jpg)

---

## 🛡 Indicators of Compromise (IOCs)
| Type | Value |
| :--- | :--- |
| **Malicious URL** | [span_24](start_span)`https://securesupport.vercel.app/`[span_24](end_span) |
| **Hosting Platform** | [span_25](start_span)Vercel (Cloud App)[span_25](end_span) |
| **Subject Line** | [span_26](start_span)Phishing Email Content & URL Investigation – Credential Harvesting Attempt[span_26](end_span) |
| **Technique** | [span_27](start_span)Credential Harvesting / Subdomain Squatting[span_27](end_span) |

---

## ⚠️ Risk Assessment
**[span_28](start_span)[span_29](start_span)Threat Level:** High[span_28](end_span)[span_29](end_span)
If an administrative employee submits credentials:
1. **[span_30](start_span)Administrative Compromise:** Direct loss of high-privilege account control[span_30](end_span).
2. **[span_31](start_span)Lateral Movement:** Attackers could move within the NexShield network[span_31](end_span).
3. **[span_32](start_span)Data Exfiltration:** Potential for unauthorized data access and ransomware deployment[span_32](end_span).

---

## 💡 Mitigation & Recommendations

### Immediate Actions
* **[span_33](start_span)DNS Filtering:** Block the `securesupport.vercel.app` subdomain using tools like Cisco Umbrella or Cloudflare Gateway[span_33](end_span).
* **[span_34](start_span)MFA Enforcement:** Ensure hardware-based (FIDO2) or app-based MFA is mandatory for all admin accounts[span_34](end_span).
* **[span_35](start_span)Endpoint Monitoring:** Deploy EDR solutions to monitor for unusual login patterns[span_35](end_span).

### Long-Term Strategy
* **[span_36](start_span)Advanced Email Filtering:** Configure gateways to flag external emails containing keywords like "Verify" alongside cloud links[span_36](end_span).
* **[span_37](start_span)Security Awareness:** Conduct monthly phishing simulations focusing on "Living off the Cloud" tactics[span_37](end_span).
* **[span_38](start_span)Employee Education:** Encourage the "Think Before You Click" protocol and use of "Report Phish" buttons[span_38](end_span).

---

## 🎓 Lessons Learned
* **[span_39](start_span)[span_40](start_span)Tool Proficiency:** Gained hands-on experience with VirusTotal, Urlscan.io, and Cisco Talos[span_39](end_span)[span_40](end_span).
* **[span_41](start_span)De-obfuscation:** Learned techniques for safely reconstructing mangled malicious links[span_41](end_span).
* **[span_42](start_span)Cloud Threats:** Developed an understanding of how attackers abuse trusted cloud providers (Vercel) to bypass filters[span_42](end_span).


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
