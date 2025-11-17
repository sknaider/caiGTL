# GTL AI Security Platform - Demo Script

**Version**: 1.0
**Duration**: 15 minutes
**Target Audience**: CIOs, Security Managers, IT Directors at logistics companies

---

## Pre-Demo Checklist

**24 Hours Before Demo**:
- [ ] Confirm demo time and attendees
- [ ] Send calendar invite with Zoom/Teams link
- [ ] Email pre-demo questionnaire (see below)
- [ ] Prepare demo environment with prospect's industry (logistics/medical/etc.)
- [ ] Load sample scan results relevant to their tech stack
- [ ] Test screen sharing and audio

**Pre-Demo Questionnaire** (send via email):
```
Subject: Quick Questions Before Our GTL Demo Tomorrow

Hi [Name],

Looking forward to our demo tomorrow at [time]. To make this as relevant as possible, could you quickly answer:

1. What security tools do you currently use? (pentesting, SIEM, etc.)
2. How many locations/systems do you need to monitor?
3. Biggest security pain point right now?
4. Any specific compliance requirements? (SUNAT, HIPAA, ISO 27001)

Thanks!
[Your name]
```

**15 Minutes Before Demo**:
- [ ] Open GTL dashboard (logged in)
- [ ] Open sample scan report (PDF)
- [ ] Open pricing sheet
- [ ] Have demo environment ready
- [ ] Close all irrelevant tabs/applications
- [ ] Set phone to silent

---

## Demo Script (15 Minutes)

### 0:00-0:02 | Opening & Agenda (2 min)

**Script**:

> *"Hi [Name], thanks for joining! I'm [Your Name] from GTL AI Security. Over the next 15 minutes, I'll show you how companies like yours are replacing expensive manual pentesting with automated, continuous security scanning—saving 60-90% on costs while actually improving security coverage."*

> *"Here's what we'll cover:*
> 1. *Quick platform overview (3 min)*
> 2. *Live scan demo (5 min)*
> 3. *Reporting & alerts (3 min)*
> 4. *Pricing & next steps (4 min)"*

> *"Sound good? Great. And feel free to interrupt with questions anytime."*

**Notes**:
- Keep energy high but professional
- Confirm they can see your screen
- Note who's on the call and their roles

---

### 0:02-0:05 | Problem Statement (3 min)

**Script**:

> *"Let me start with why we built this. We talked to 50+ logistics companies in Peru, and they all told us the same 3 problems:"*

**Show slide or whiteboard**:

```
❌ Problem 1: Manual pentesting costs $15K-50K per test
   → Most companies can only afford 1-2 tests per year
   → Leaves 99% of the year with blind spots

❌ Problem 2: Generic security tools miss logistics-specific issues
   → They don't understand EDI systems, bill of lading, SUNAT compliance
   → You need expensive consultants to configure them

❌ Problem 3: Security talent shortage
   → Hard to find qualified analysts in Peru
   → Expensive when you do ($60K+ per year)
```

> *"Does this sound familiar? [PAUSE for response]*

> *"Right. So we built GTL specifically for logistics companies. It automates the pentesting using AI agents that understand your industry—EDI, warehouse systems, GPS trackers, customs data—and it runs continuously, not just once a year."*

**Transition**:
> *"Let me show you how it works..."*

---

### 0:05-0:08 | Platform Overview (3 min)

**Show GTL Dashboard** (main screen):

> *"This is the GTL dashboard. Think of it as your security control center."*

**Point to key areas**:

1. **Top Navigation**:
   > *"Up here you've got Scans, Vulnerabilities, Reports, and Settings."*

2. **Overview Widget** (center):
   ```
   ┌─────────────────────────────────────┐
   │  Security Score: 87/100    ↑ +12    │
   │  Critical Issues: 0                 │
   │  High Priority: 3                   │
   │  Last Scan: 2 hours ago             │
   └─────────────────────────────────────┘
   ```
   > *"Your overall security posture at a glance. Notice we just ran a scan 2 hours ago—this runs automatically on a schedule you set."*

3. **Target Systems** (left sidebar):
   ```
   ✅ EDI System (X12) - 192.168.10.50
   ✅ SAP WMS - 192.168.10.75
   ⚠️  TMS (Oracle) - 192.168.10.100 (3 issues)
   ✅ GPS Tracking - 192.168.20.15
   ```
   > *"These are your monitored systems. Green means secure, yellow means issues found."*

4. **Recent Activity** (right panel):
   > *"Real-time feed of what the platform is doing—scans running, vulnerabilities found, issues fixed."*

**Key Message**:
> *"The beauty is, you set this up once, and it just runs. Your team gets alerts when something critical pops up, but otherwise, it's hands-off."*

---

### 0:08-0:13 | Live Scan Demo (5 min)

**Navigate to: Scans → Create New Scan**

> *"Let me show you how easy it is to run a scan. Say you just deployed a new warehouse management system and want to check it for vulnerabilities."*

**Fill out scan form**:
```
Profile: Logistics & Supply Chain ▼
Target: 192.168.10.100 (TMS Server)
Tools: ☑ nmap  ☑ nuclei  ☑ nikto  ☑ sqlmap
Schedule: One-time (now)
```

> *"See these profiles? We've pre-configured them for different industries. For logistics, it automatically checks for EDI vulnerabilities, bill of lading fraud, GPS tracking issues—stuff that generic tools miss."*

**Click "Start Scan"**

**While scan runs (30 seconds)**:

> *"While this is running, let me point out a few things:"*

**Show scan progress**:
```
┌─────────────────────────────────────┐
│  Scan Status: Running...            │
│  ├─ nmap: Completed ✅              │
│  ├─ nuclei: Running... 45%          │
│  ├─ nikto: Queued                   │
│  └─ sqlmap: Queued                  │
│                                     │
│  Elapsed: 0:02:15                   │
│  Estimated remaining: 0:04:30       │
└─────────────────────────────────────┘
```

> *"It's running multiple tools in parallel—network discovery, web vulnerability scanning, SQL injection testing. Normally this would take a security analyst 4-6 hours to do manually. We're doing it in under 5 minutes."*

**Scan completes**:

**Show results summary**:
```
┌─────────────────────────────────────┐
│  Scan Complete!                     │
│                                     │
│  Total Vulnerabilities: 12          │
│  ├─ Critical (CVSS 9-10):  1 🔴    │
│  ├─ High (CVSS 7-8.9):     4 🟠    │
│  ├─ Medium (CVSS 4-6.9):   5 🟡    │
│  └─ Low (CVSS 0-3.9):      2 ⚪     │
└─────────────────────────────────────┘
```

> *"Okay, we found 12 vulnerabilities. Let's look at this critical one..."*

**Click on Critical Vulnerability**:

```
╔═══════════════════════════════════════════════════╗
║ Critical: SQL Injection in Login Form            ║
╠═══════════════════════════════════════════════════╣
║ CVSS Score: 9.8 (Critical)                        ║
║ System: TMS (Oracle) - 192.168.10.100            ║
║ Tool: sqlmap                                      ║
║ Description: SQL injection vulnerability in the  ║
║ login form allows unauthenticated attackers to   ║
║ extract database contents or gain admin access.  ║
║                                                   ║
║ Impact:                                           ║
║ • Unauthorized access to shipment data           ║
║ • Customer information theft                      ║
║ • Bill of lading manipulation                     ║
║                                                   ║
║ Remediation:                                      ║
║ 1. Use parameterized queries (not string concat) ║
║ 2. Apply input validation on login fields        ║
║ 3. Update TMS to version 12.5.3 (security patch) ║
║                                                   ║
║ References:                                       ║
║ • CVE-2024-12345                                  ║
║ • OWASP Top 10: A03:2021 – Injection             ║
╚═══════════════════════════════════════════════════╝
```

> *"See how detailed this is? It's not just 'you have a SQL injection.' It tells you exactly where it is, what the impact could be—in logistics terms like bill of lading manipulation—and most importantly, how to fix it. Step-by-step remediation."*

**Key Point**:
> *"This is the kind of thing that could lead to a major breach. Imagine someone manipulating bills of lading or stealing shipment data. We just found this in 5 minutes. How long would it take in a manual pentest? [PAUSE] Weeks or months, if they even found it at all."*

---

### 0:13-0:16 | Reporting & Alerts (3 min)

**Navigate to: Reports**

> *"Now let's talk about reporting, because this is where clients really love us."*

**Show report list**:
```
┌───────────────────────────────────────────────────┐
│ Recent Reports                                    │
├───────────────────────────────────────────────────┤
│ 📄 Weekly Security Summary - Nov 15, 2025        │
│    Format: PDF (Spanish) | Status: ✅ Sent       │
│                                                   │
│ 📄 EDI System Security Audit - Nov 10, 2025      │
│    Format: PDF + HTML | Status: ✅ Sent          │
│                                                   │
│ 📄 SUNAT Compliance Report - Nov 1, 2025         │
│    Format: PDF (Spanish) | Status: ✅ Sent       │
└───────────────────────────────────────────────────┘
```

**Open a PDF report** (screen share):

> *"Here's a weekly report we sent to a client. Notice it's in Spanish—we're the only platform that does native Spanish reports for the Peruvian market."*

**Scroll through PDF**:
- Page 1: Executive Summary
  > *"Executive summary for your CIO—high-level risks, security score trend, key recommendations."*

- Page 2-3: Vulnerability Details
  > *"Technical details for your security team—CVSS scores, affected systems, remediation steps."*

- Page 4: Compliance Matrix
  > *"And here's the compliance section. This client needs SUNAT compliance, so we automatically check if their customs data protection is up to standard. Saves them 40+ hours of manual audit prep."*

**Go back to Dashboard → Settings → Alerts**:

> *"One more thing—alerts. You can configure exactly how you want to be notified."*

**Show alert configuration**:
```
┌─────────────────────────────────────┐
│ Alert Channels                      │
├─────────────────────────────────────┤
│ ☑ Email: security@company.com       │
│ ☑ Slack: #security-alerts           │
│ ☐ PagerDuty                          │
│ ☐ Microsoft Teams                    │
│ ☑ Webhook (custom integration)      │
│                                     │
│ Severity Thresholds:                │
│ ├─ Critical: Immediate alert 🔴    │
│ ├─ High: Within 1 hour 🟠          │
│ ├─ Medium: Daily digest 🟡         │
│ └─ Low: Weekly summary ⚪           │
└─────────────────────────────────────┘
```

> *"So if we find a critical vulnerability like that SQL injection, you get an immediate Slack or email alert. Medium/low stuff goes into a weekly digest so you're not overwhelmed."*

**Key Message**:
> *"The goal is actionable intelligence, not alert fatigue. You only hear from us when there's something that actually matters."*

---

### 0:16-0:19 | Pricing & ROI (3 min)

**Share screen: Pricing sheet**

> *"Okay, let's talk about cost. We have 3 tiers based on company size and needs."*

**Show pricing tiers**:

```
┌─────────────────────────────────────────────────┐
│ TIER 1: Automated Vulnerability Assessment      │
│ $8,000 setup + $2,000/month                     │
│ • Weekly scans                                   │
│ • Up to 3 target systems                         │
│ • Email support (48h response)                   │
│ Best for: 1-50 employees                         │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ TIER 2: Continuous Threat Detection ⭐ POPULAR  │
│ $15,000 setup + $5,000/month                    │
│ • Daily scans                                    │
│ • Up to 10 target systems                        │
│ • Real-time threat detection                     │
│ • Slack/webhook integration                      │
│ • Phone support (24h response)                   │
│ Best for: 50-500 employees                       │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ TIER 3: AI-Powered SOC-as-a-Service             │
│ $30,000 setup + $10,000/month                   │
│ • Continuous monitoring                          │
│ • Unlimited systems                              │
│ • Dedicated security analyst (20 hrs/month)     │
│ • Custom agent development                       │
│ • 99.9% SLA guarantee                            │
│ Best for: 500+ employees                         │
└─────────────────────────────────────────────────┘
```

> *"Based on what you told me—[X employees, Y systems]—I'd recommend Tier [1/2/3]. Here's why..."*

**Show ROI calculation**:

> *"Now, let's talk ROI. What are you spending on security today?"*

**[Listen to answer, then show comparison]**

```
Traditional Approach (what you're probably doing now):
├─ Quarterly manual pentests: $20K × 4 = $80,000/year
├─ Security analyst time: $60,000/year
└─ Total: $140,000/year

GTL Platform (Tier 2):
├─ Setup: $15,000 (one-time)
├─ Annual: $5,000 × 12 = $60,000/year
└─ Year 1 Total: $75,000
└─ Year 2+ Total: $60,000/year

Savings:
├─ Year 1: $65,000 (46% cost reduction)
├─ Year 2: $80,000 (57% cost reduction)
└─ 3-Year Savings: $225,000
```

> *"So you're saving $65K-80K per year. But here's the kicker—you're also getting:"*
> - *Continuous monitoring instead of 4 point-in-time snapshots*
> - *Logistics-specific security checks*
> - *SUNAT compliance automation*
> - *Spanish reports*

**Handle pricing objections** (see Objection Handling below)

---

### 0:19-0:20 | Next Steps & Close (1 min)

**Script**:

> *"So here's what I suggest as next steps:"*

**Option A - Hot Lead**:
> *"We have a 30-day free trial—no credit card required. I can get you set up this week, and you can run your first scans by Friday. Sound good?"*

**Option B - Warm Lead**:
> *"Let me send you a pilot proposal. We'll do a 30-day proof of concept where we scan 3 of your systems and show you exactly what vulnerabilities we find. If you like what you see, we convert to a paid plan. Fair?"*

**Option C - Need More Info**:
> *"What additional information do you need to move forward? I can set up a technical deep dive with our solutions architect, or I can send you a case study from [similar company]."*

**Always end with a specific action**:
> *"Can we schedule a follow-up for [specific day/time] to [specific action]?"*

---

## Post-Demo Follow-Up

**Within 1 Hour**:
- [ ] Send thank-you email
- [ ] Attach demo recording (if permitted)
- [ ] Include pricing sheet
- [ ] Include relevant case study
- [ ] Schedule follow-up meeting

**Email Template**:
```
Subject: GTL Demo Follow-Up + Next Steps

Hi [Name],

Great talking with you today! As promised, here are the materials:

📹 Demo Recording: [link]
💰 Pricing Sheet: [attached]
📊 Case Study (Transportes Rápidos): [attached]
🚀 Free Trial Signup: https://gtl.pe/trial

Based on our conversation, I think Tier [X] is the best fit for [Company] because [reason].

Next steps:
1. [Specific action - e.g., "Review the pricing sheet"]
2. [Specific action - e.g., "Discuss with your team"]
3. [Specific action - e.g., "Meet again on [date] to kick off trial"]

Let me know if you have any questions!

Best,
[Your name]
```

**Within 24 Hours**:
- [ ] Log demo notes in CRM
- [ ] Set follow-up reminder
- [ ] Send to account team if qualified lead

---

## Objection Handling

### Objection 1: "We already have [Darktrace/Vectra/etc.]"

**Response**:
> *"Great! Those are solid platforms for network detection. Where we differentiate is logistics-specific security—EDI, warehouse systems, GPS tracking, SUNAT compliance. Most clients use us alongside Darktrace for full coverage. Can I show you a side-by-side comparison?"*

**Show**: Technical_Comparison.md

---

### Objection 2: "Too expensive"

**Response**:
> *"I understand budget is tight. Let me ask—what are you spending on manual pentesting right now? [WAIT FOR ANSWER] So at $X/year, you're actually spending more for quarterly snapshots than you would for continuous monitoring with GTL. Plus, we have a pilot program with 50% off the first 3 months. Want to try that?"*

**Alternative**:
> *"We also have Tier 1 at $2K/month—$8K setup, then $24K/year. That's less than the cost of a single manual pentest, but you get weekly scans all year. Would that fit your budget better?"*

---

### Objection 3: "We need to think about it"

**Response**:
> *"Totally understand. Let me make this easier—what specific questions do you still have? Is it technical fit, budget, timing, or something else?"*

**[Listen, then address specific concern]**

> *"Here's what I suggest: Let's do a free proof of concept. No commitment, no credit card. We'll scan 3 of your systems and show you exactly what we find. Then you can make an informed decision. Fair?"*

---

### Objection 4: "We don't have time to implement this right now"

**Response**:
> *"Good news—setup takes 2-5 days, not weeks. Most of that is our team doing the configuration. On your end, you need about 4 hours total:*
> - *2 hours for initial setup meeting*
> - *1 hour for team training*
> - *1 hour for review and go-live*

> *We can schedule it around your availability. And honestly, the longer you wait, the more time vulnerabilities have to be exploited. That SQL injection I showed you? That's a ticking time bomb."*

---

### Objection 5: "We need this approved by [CIO/CFO/Board]"

**Response**:
> *"Of course. What does your approval process look like? [LISTEN] Okay, so to help you make the case, let me send you:*
> 1. *Executive summary (1-pager with ROI)*
> 2. *Technical comparison vs. alternatives*
> 3. *Case study from similar company*
> 4. *Pilot proposal (proof of concept)*

> *Would it help if I joined your meeting with [CIO/CFO] to answer technical questions?"*

---

### Objection 6: "We have an in-house security team"

**Response**:
> *"That's great—having internal expertise is huge. Here's how we help teams like yours:*
> 1. *We automate the repetitive stuff (weekly scans, compliance checks) so your team can focus on high-value work*
> 2. *We provide additional coverage for logistics-specific issues your general tools might miss*
> 3. *We give your team better data to make decisions*

> *Think of us as force multipliers for your team, not replacements. Want to talk to your security lead and see if there are gaps we can fill?"*

---

## Demo Tips & Best Practices

### DO's ✅

1. **Personalize the demo**
   - Use their company name in examples
   - Show vulnerabilities relevant to their tech stack
   - Reference their industry (if medical logistics, show HIPAA features)

2. **Keep it interactive**
   - Ask questions every 2-3 minutes
   - Pause for reactions
   - "Does this make sense?" "Have you seen this problem?"

3. **Focus on business value, not features**
   - Don't say: "We have a nuclei integration"
   - Do say: "We automatically check for web vulnerabilities that could lead to data breaches"

4. **Use the magic number: 90%**
   - "90% cost savings vs. manual pentesting"
   - "90% reduction in critical vulnerabilities"
   - "90% less time spent on compliance prep"

5. **Tell stories**
   - Reference real client examples
   - "One of our clients found 23 critical vulnerabilities in the first scan..."
   - Use Case_Study_Template.md

### DON'Ts ❌

1. **Don't talk about yourself**
   - Avoid: "I've been in security for 10 years..."
   - Focus on THEM: "Tell me about your current security setup..."

2. **Don't use jargon**
   - Avoid: "Our agentic AI framework leverages LLMs for vulnerability contextualization..."
   - Say: "Our AI agents understand your systems and explain vulnerabilities in plain language"

3. **Don't show everything**
   - Pick 3-5 key features, not all 50
   - Save advanced features for follow-up technical deep dive

4. **Don't badmouth competitors**
   - Avoid: "Darktrace is overpriced and doesn't work"
   - Say: "Darktrace is great for network detection. We focus on application security and logistics-specific issues."

5. **Don't end without next steps**
   - Always schedule the follow-up meeting before hanging up
   - "Let's put 30 minutes on the calendar for [date] to [action]"

---

## Demo Environment Setup

### Create Demo Data

**Option 1: Use Staging Environment**
```bash
# Deploy GTL to demo environment
docker-compose -f docker-compose.demo.yml up -d

# Load sample data
python scripts/load_demo_data.py \
  --industry logistics \
  --company "Demo Logistics SAC" \
  --systems 5
```

**Option 2: Use Screenshots/Video**
- Record real scans in advance
- Edit to show vulnerabilities relevant to prospect
- Use screen recording for consistency

### Demo Checklist

- [ ] Dashboard shows 85-90 security score (aspirational)
- [ ] 1-2 critical vulnerabilities visible (to show value)
- [ ] Recent scan completed in last 2 hours (shows it's active)
- [ ] Sample report in Spanish (for Peruvian market)
- [ ] Alert configuration showing Slack/email integration
- [ ] Compliance dashboard showing SUNAT/Ley 29733

---

## Success Metrics

Track these metrics for every demo:

| Metric | Target | Actual |
|--------|--------|--------|
| **Demo Scheduled → Demo Held** | 80% | ___ |
| **Demo Held → Trial Started** | 40% | ___ |
| **Trial Started → Paid Customer** | 60% | ___ |
| **Average Deal Size** | $75K (Tier 2) | ___ |
| **Sales Cycle Length** | 30-45 days | ___ |

---

## Frequently Asked Questions

**Q: What if the live scan fails during the demo?**
**A**: Have a backup video recording. Say: "Looks like the network is slow—let me show you a recording of a recent scan instead."

**Q: What if they ask about certifications (SOC 2, ISO 27001)?**
**A**: "We're SOC 2 Type II certified (as of [date]). ISO 27001 certification is in progress (expected [Q1 2026]). In the meantime, we can provide our security documentation for your review."

**Q: What if they ask about uptime SLA?**
**A**:
- Tier 1: 99.0% uptime
- Tier 2: 99.5% uptime
- Tier 3: 99.9% uptime with financial penalties for misses

**Q: What if they want to see the code?**
**A**: "Our core platform is proprietary, but we use the open-source CAI framework (MIT license) for agent development. You can review that code at github.com/AliasRobotics/cai. We also provide full API documentation for custom integrations."

**Q: What if they ask about data security?**
**A**:
- All data encrypted at rest (AES-256) and in transit (TLS 1.3)
- SOC 2 Type II certified
- On-premises deployment available (your data never leaves your network)
- RBAC (role-based access control)
- Full audit logging

---

## Contact & Resources

**Sales Team**: sales@gtl.pe | +51 1 234 5678

**Demo Resources**:
- Demo Environment: https://demo.gtl.pe
- Screen Recording: [Loom/Vimeo link]
- Case Studies: gtl-ai-security/docs/sales/
- Technical Docs: gtl-ai-security/docs/technical/

---

**Demo Script Version**: 1.0
**Last Updated**: November 2025
**Owner**: GTL Sales Team
