🛡️ CYBER SHIELD — Scam-Risk Awareness, Prevention & Response Assistant
License: MIT
Technology
Privacy
Accessibility

A lightweight, first-line digital safety assistant that helps users evaluate suspicious messages, understand manipulative red flags, and follow structured response and reporting protocols.

[!IMPORTANT]
Educational Prototype Disclaimer
CYBER SHIELD is an educational awareness aid, NOT a replacement for law enforcement, banking fraud departments, or professional cyber-forensic investigation tools.

Never enter active banking credentials, PINs, OTPs, CVVs, passwords, or government identity numbers.
A "Low Risk" rating does NOT guarantee that a message is safe. Always verify independently through official, verified channels.
📌 Table of Contents
✨ Key Features
🔄 7-Step Demonstration Flow
🔒 Safety & Privacy by Design
📂 Repository Structure
🚀 Quick Start Guide
🛠️ Technology Stack
🧠 Detection Engine & Heuristics
🚨 Emergency Helplines (India)
🔮 Innovation & Roadmap
🤝 Contributing
📄 License
✨ Key Features
🔍 Multi-Vector Scam Analysis: Evaluates SMS/WhatsApp, Phone Calls, UPI Requests, APK/App Downloads, Job Offers, Fake Investments, Phishing Emails, and AI Impersonations.
🚩 Explainable Red Flags: Demystifies the psychology behind scams (urgency, fear, greed, fake authority) with clear, human-readable explanations instead of a generic "fraud" badge.
⚖️ Side-by-Side Message Comparator: Compares two similar messages (e.g., authentic bank notification vs. phishing lure) to train users on spotting subtle anomalies.
🌲 Incident Response Decision Tree: Step-by-step triage based on user status (e.g., money sent, credentials exposed, unknown APK installed, or early catch).
🔗 Passive URL Heuristic Engine: Analyzes suspicious domains, typosquatting, lookalikes (amaz0n, g00gle), and risky TLDs (.xyz, .tk) without ever opening or visiting the URL.
🗣️ Senior-Citizen & Accessibility Mode: Integrated browser Read Aloud (TTS), Large Text mode, dark/light themes, and high-contrast touch targets.
📊 Real-Time Awareness Dashboard: Tracks anonymous session metrics (most flagged scam categories and common red flags).
🎓 Interactive Quiz & Learning Center: Practical quizzes and breakdowns of social engineering vectors.
🔄 7-Step Demonstration Flow
mermaid

graph TD
    A[Step 1: Select Incident Type] --> B[Step 2: Submit Text, URL, or Screenshot]
    B --> C[Step 3: Rule-Based Risk Engine & URL Heuristics]
    C --> D[Step 4: Output Normalized Risk Score 0-100 & Category]
    D --> E[Step 5: Explain Psychological Red Flags]
    E --> F[Step 6: Prescribe Immediate Actions Do's and Don'ts]
    F --> G[Step 7: Provide Verified Official Reporting Channels]
Step 1 — Describe the Incident: Select from 10 common scenarios (UPI, Job Scam, KYC Threat, etc.).
Step 2 — Submit Evidence: Paste sample text, enter a suspicious URL, or drop a masked screenshot.
Step 3 — Risk Analysis: 30+ regex rules check for urgency triggers, credential requests, threats, and suspicious links.
Step 4 — Risk Score & Category: Normalized score (0–100) mapped to Low, Medium, or High Risk.
Step 5 — Explain Red Flags: Clear explanations breakdown manipulative language (e.g., "Creates false panic to prevent verification").
Step 6 — Immediate Actions: Clear, actionable steps (e.g., "Do not click", "Freeze card", "Preserve screenshots").
Step 7 — Report / Escalate: Direct links and numbers for verified cybercrime helplines (e.g., 1930, cybercrime.gov.in).
🔒 Safety & Privacy by Design
100% Client-Side Processing: No back-end database, no remote API logging, and no analytics trackers. Everything runs locally inside the user's browser.
Zero Malicious Execution: Suspicious URLs and APK links are parsed purely as text strings—never fetched, requested, or executed.
Privacy-First Screenshot Handling: Images uploaded via drag-and-drop are loaded strictly into memory using the HTML5 FileReader API and are discarded upon reload.
Separation of Concerns: Emergency guidance and verified reporting information are kept structurally distinct from AI/heuristic scores.
