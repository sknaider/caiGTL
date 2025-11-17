# GTL AI Security - Case Study Template

**Purpose**: Use this template to document client success stories for sales and marketing materials.

**Instructions**:
1. Complete all sections with specific, quantifiable data
2. Get written approval from client before publication
3. Anonymize if client requests (use "A leading logistics company in Peru...")
4. Include before/after metrics where possible
5. Save completed case study as: `Case_Study_[ClientName]_[Year].md`

---

## Case Study: [Client Company Name]

**Industry**: [e.g., Logistics & Supply Chain, Medical Logistics, E-commerce]
**Location**: [City, Peru]
**Company Size**: [Number of employees]
**GTL Tier**: [Tier 1 / Tier 2 / Tier 3]
**Deployment Date**: [Month Year]
**Case Study Date**: [Month Year]

---

## Executive Summary

**In 3-4 sentences, summarize:**
- Client's business and security challenge
- GTL solution implemented
- Key results achieved
- Primary business impact

**Example**:
> *Transportes Rápidos del Perú SAC, a leading logistics provider with 200+ trucks, struggled with manual security audits that missed critical EDI vulnerabilities. After deploying GTL AI Security Platform (Tier 2), they discovered 23 high-risk vulnerabilities in the first month, prevented a ransomware attack, and achieved SUNAT compliance—saving $85,000 in Year 1 while reducing security incidents by 95%.*

---

## Company Background

### Business Overview
- **What does the company do?** [Core business activities]
- **Annual revenue**: [If public/permissible]
- **Employees**: [Number]
- **Locations**: [Number of facilities/warehouses]
- **Technology stack**: [Key systems: SAP, Oracle WMS, TMS, EDI, etc.]

### Industry Context
- **Regulatory requirements**: [SUNAT, Ley 29733, HIPAA, etc.]
- **Key assets to protect**: [Customer data, shipment info, GPS tracking, etc.]
- **Threat landscape**: [Common threats faced]

---

## The Challenge

### Primary Pain Points

**List 3-5 specific challenges the client faced before GTL:**

1. **[Challenge 1 - Security Gap]**
   - Description: [What was the problem?]
   - Impact: [How did it affect the business?]
   - Cost: [Quantify if possible - dollars, hours, incidents]

2. **[Challenge 2 - Compliance]**
   - Description: [What compliance issues existed?]
   - Impact: [Risk exposure, potential fines]
   - Cost: [Time/money spent on manual compliance]

3. **[Challenge 3 - Operational]**
   - Description: [Manual processes, lack of visibility, etc.]
   - Impact: [Business disruption, resource drain]
   - Cost: [Opportunity cost, analyst hours]

### Before GTL - Baseline Metrics

| Metric | Before GTL |
|--------|-----------|
| **Security Assessments per Year** | [e.g., 2 manual pentests] |
| **Time to Detect Vulnerabilities** | [e.g., 60-90 days] |
| **Time to Remediate Critical Issues** | [e.g., 30 days] |
| **Security Incidents per Year** | [e.g., 4-6 incidents] |
| **Compliance Audit Prep Time** | [e.g., 120 hours] |
| **Annual Security Budget** | [e.g., $120,000] |
| **Critical Vulnerabilities Open** | [e.g., 15-20 at any time] |

---

## The Solution

### GTL Platform Configuration

**Tier Selected**: [Tier 1 / Tier 2 / Tier 3]

**Why this tier?**
[1-2 sentences explaining tier selection based on company size, needs, budget]

**Deployment Model**: [Cloud / On-Premises / Hybrid]

### Scan Profile Configuration

**Industry Profile**: [Logistics / Medical AI / E-commerce / Custom]

**Target Systems** (list all):
1. [e.g., EDI System (X12) - 192.168.10.50]
2. [e.g., SAP WMS - 192.168.10.75]
3. [e.g., TMS (Oracle) - 192.168.10.100]
4. [e.g., GPS Tracking Server - 192.168.20.15]
5. [e.g., Customer Portal - https://portal.client.com]

**Tools Enabled**:
- ✅ nmap (Network Discovery)
- ✅ nuclei (Web Vulnerabilities)
- ✅ nikto (Advanced Web Scanning)
- ✅ sqlmap (SQL Injection Testing)
- ✅ [Custom tool if applicable]

**Scan Frequency**: [Daily / Weekly / Continuous]

**Custom Agents Developed** (if any):
1. [Agent name and purpose]
2. [Agent name and purpose]

### Integration Setup

**Alerting Channels**:
- ✅ Email: [security@client.com]
- ✅ Slack: [#security-alerts channel]
- ⬜ PagerDuty
- ⬜ SIEM (specify which)

**Reporting**:
- **Format**: [PDF / HTML / JSON]
- **Language**: [Spanish / English]
- **Frequency**: [Weekly digest / Real-time alerts]
- **Recipients**: [CIO, Security Manager, IT Director]

### Implementation Timeline

| Week | Milestone | Status |
|------|-----------|--------|
| Week 1 | Platform deployment & configuration | ✅ Completed |
| Week 1 | Initial vulnerability scan | ✅ Completed |
| Week 2 | Team training (2 sessions) | ✅ Completed |
| Week 2 | Remediation planning | ✅ Completed |
| Week 3-4 | High-priority vulnerability fixes | ✅ Completed |
| Week 4 | Go-live (automated scans) | ✅ Completed |

**Total Setup Time**: [X days/weeks]

---

## Results & Impact

### Immediate Wins (First 30 Days)

**Vulnerabilities Discovered**:
- **Total vulnerabilities found**: [Number]
  - Critical (CVSS 9.0-10.0): [Number]
  - High (CVSS 7.0-8.9): [Number]
  - Medium (CVSS 4.0-6.9): [Number]
  - Low (CVSS 0.1-3.9): [Number]

**Notable Findings**:
1. **[Critical Finding 1]**
   - System: [Which system]
   - Issue: [Description]
   - Risk: [Potential impact - data breach, ransomware, etc.]
   - Remediation: [How it was fixed]

2. **[Critical Finding 2]**
   - System: [Which system]
   - Issue: [Description]
   - Risk: [Potential impact]
   - Remediation: [How it was fixed]

### After GTL - Performance Metrics (6 Months)

| Metric | Before GTL | After GTL | Improvement |
|--------|-----------|-----------|-------------|
| **Security Assessments per Year** | [e.g., 2] | [e.g., 52 (weekly)] | +2500% |
| **Time to Detect Vulnerabilities** | [e.g., 60-90 days] | [e.g., < 24 hours] | -97% |
| **Time to Remediate Critical Issues** | [e.g., 30 days] | [e.g., 7 days] | -77% |
| **Security Incidents per Year** | [e.g., 4-6] | [e.g., 0-1] | -85% |
| **Compliance Audit Prep Time** | [e.g., 120 hours] | [e.g., 20 hours] | -83% |
| **Critical Vulnerabilities Open** | [e.g., 15-20] | [e.g., 0-2] | -90% |

### Business Impact

**1. Cost Savings**

```
Manual Pentesting (Eliminated):     $80,000/year
Security Analyst Time Saved:        $18,000/year (30 hrs/month @ $50/hr)
Compliance Prep Time Saved:         $15,000/year
Avoided Breach Cost (estimated):    $500,000 (one-time)
─────────────────────────────────────────────
Total Year 1 Value:                 $613,000

GTL Platform Cost (Tier 2):        -$75,000 (Year 1)
─────────────────────────────────────────────
Net ROI Year 1:                     $538,000 (717% ROI)
```

**2. Operational Efficiency**

- **Reduced manual work**: [X hours/week saved]
- **Faster incident response**: [X% improvement]
- **Automated compliance reporting**: [X hours/month saved]

**3. Risk Reduction**

- **Prevented incidents**: [Number and type - e.g., "Blocked ransomware attack, prevented data breach"]
- **Compliance achieved**: [Which regulations - e.g., "SUNAT compliant, Ley 29733 validated"]
- **Security posture**: [Qualitative improvement - e.g., "From reactive to proactive security"]

---

## Client Testimonial

**[Client Name]**
*[Title, Company]*

> "[Quote from client about their experience with GTL Platform. Should cover: problem faced, decision to choose GTL, results achieved, recommendation. 3-5 sentences ideal.]"

**Example**:
> *"Before GTL, we were flying blind between quarterly pentests. We discovered critical EDI vulnerabilities that our manual auditors completely missed. The platform paid for itself in the first month by preventing a ransomware attack. GTL is now an essential part of our security operations—I can't imagine going back to manual-only testing."*
> — **Carlos Mendoza**, CTO, Transportes Rápidos del Perú SAC

---

## Technical Deep Dive (Optional)

### Notable Security Findings

**Finding #1: [Vulnerability Name]**

- **System**: [EDI System X12]
- **CVSS Score**: [9.8 (Critical)]
- **Description**: [Technical details of the vulnerability]
- **Proof of Concept**: [How GTL detected it]
- **Impact**: [What could have happened - data exfiltration, unauthorized access, etc.]
- **Remediation**: [How it was fixed - patch applied, configuration change, etc.]
- **Timeline**:
  - Detected: [Date]
  - Reported: [Date]
  - Remediated: [Date]
  - Verified: [Date]

**Finding #2: [Vulnerability Name]**

[Same structure as Finding #1]

### Custom Agent Development (if applicable)

**Agent Name**: [e.g., "SUNAT Customs Data Validator"]

**Purpose**: [What business problem does it solve?]

**How it Works**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Results**: [Vulnerabilities found, time saved, compliance achieved]

---

## Lessons Learned

### What Worked Well

1. **[Success Factor 1]**
   - [Description of what contributed to success]

2. **[Success Factor 2]**
   - [Description of what contributed to success]

3. **[Success Factor 3]**
   - [Description of what contributed to success]

### Challenges Overcome

1. **[Challenge 1]**
   - Issue: [What went wrong or was difficult]
   - Solution: [How it was resolved]

2. **[Challenge 2]**
   - Issue: [What went wrong or was difficult]
   - Solution: [How it was resolved]

### Recommendations for Future Clients

- **[Recommendation 1]**: [Advice based on this client's experience]
- **[Recommendation 2]**: [Advice based on this client's experience]
- **[Recommendation 3]**: [Advice based on this client's experience]

---

## Next Steps & Future Plans

### Current Status

- **Tier**: [Current tier]
- **Systems Monitored**: [Number]
- **Scans per Month**: [Number]
- **Team Size Using Platform**: [Number of users]

### Planned Expansions

- ⬜ **Upgrade to Tier 3** (planned for [Month Year])
  - Reason: [Why upgrading - more systems, need SOC service, etc.]

- ⬜ **Add HIPAA Compliance Module** (planned for [Month Year])
  - Reason: [Medical logistics expansion]

- ⬜ **Expand to Additional Locations**
  - [Location 1]: [Number of new systems]
  - [Location 2]: [Number of new systems]

- ⬜ **Custom Agent Development**
  - [Agent name and purpose]

---

## Key Metrics Summary

**Quick Reference Card**:

| Metric | Value |
|--------|-------|
| **ROI (Year 1)** | [e.g., 717%] |
| **Annual Cost Savings** | [e.g., $85,000] |
| **Vulnerabilities Fixed** | [e.g., 23 critical, 67 total] |
| **Security Incidents Prevented** | [e.g., 1 ransomware attack] |
| **Time to Detect (Improvement)** | [e.g., -97%] |
| **Compliance Status** | [e.g., SUNAT ✅, Ley 29733 ✅] |
| **Payback Period** | [e.g., 2.1 months] |

---

## Contact Information

**Client** (if permission granted):
- Company: [Name]
- Contact: [Name, Title]
- Email: [email@company.com] (with permission)
- Phone: [+51 XXX XXXX] (with permission)

**GTL Account Team**:
- Account Manager: [Name]
- Solutions Engineer: [Name]
- Email: sales@gtl.pe

---

## Appendix

### Screenshots (if available)
- [ ] GTL Dashboard showing vulnerability trends
- [ ] Sample scan report (redacted)
- [ ] Compliance dashboard screenshot

### Supporting Documents
- [ ] Before/after network diagrams
- [ ] Vulnerability report samples
- [ ] Compliance audit results

### Media Assets
- [ ] Client logo (with permission)
- [ ] Photos (team, office, etc.)
- [ ] Video testimonial (if available)

---

**Case Study Status**: [Draft / Under Review / Client Approved / Published]

**Approval**:
- [ ] Technical accuracy reviewed
- [ ] Client approval received (signature/email)
- [ ] Legal review completed
- [ ] Marketing review completed

**Publication Channels**:
- [ ] Website (gtl.pe/case-studies)
- [ ] Sales collateral
- [ ] Conference presentations
- [ ] Social media (LinkedIn, Twitter)

---

**Template Version**: 1.0
**Last Updated**: November 2025
**Owner**: GTL Sales Team (sales@gtl.pe)
