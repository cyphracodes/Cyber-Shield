/**
 * CYBER SHIELD — Main Application Controller
 */

(function() {
    'use strict';

    // ============ STATE ============
    let selectedIncidentType = null;
    let lastResult = null;
    let readAloudMode = false;
    let currentQuizIndex = 0;
    let quizScore = 0;

    // ============ INITIALIZATION ============
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        initNavigation();
        initIncidentSelection();
        initInputTabs();
        initFileUpload();
        initAnalyzeButton();
        initSampleMessages();
        initCompare();
        initQuiz();
        initAccessibility();
        DecisionTree.init();

        // Character counter
        const textarea = document.getElementById('suspiciousText');
        if (textarea) {
            textarea.addEventListener('input', () => {
                document.getElementById('charCount').textContent = textarea.value.length;
            });
        }
    }

    // ============ NAVIGATION ============
    function initNavigation() {
        const links = document.querySelectorAll('.nav-link');
        links.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const section = this.dataset.section;
                showSection(section);
                links.forEach(l => l.classList.remove('active'));
                this.classList.add('active');
                // Close mobile nav
                document.getElementById('navLinks').classList.remove('open');
            });
        });

        // Hamburger
        document.getElementById('hamburger').addEventListener('click', () => {
            document.getElementById('navLinks').classList.toggle('open');
        });
    }

    function showSection(sectionId) {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('active');
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // ============ INCIDENT TYPE SELECTION ============
    function initIncidentSelection() {
        document.querySelectorAll('.incident-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.incident-btn').forEach(b => b.classList.remove('selected'));
                this.classList.add('selected');
                selectedIncidentType = this.dataset.type;
                goToStep(2);
                speakText(`Selected: ${this.querySelector('span').textContent}`);
            });
        });
    }

    // ============ INPUT TABS ============
    function initInputTabs() {
        document.querySelectorAll('.input-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.input-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.input-panel').forEach(p => p.classList.remove('active'));
                this.classList.add('active');
                const panelId = this.dataset.tab;
                document.getElementById(panelId).classList.add('active');
            });
        });
    }

    // ============ FILE UPLOAD ============
    function initFileUpload() {
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('screenshotInput');
        const preview = document.getElementById('imagePreview');
        const previewImg = document.getElementById('previewImg');
        const removeBtn = document.getElementById('removeImage');

        if (!uploadZone) return;

        uploadZone.addEventListener('click', () => fileInput.click());

        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.style.borderColor = 'var(--primary)';
            uploadZone.style.background = 'var(--primary-light)';
        });

        uploadZone.addEventListener('dragleave', () => {
            uploadZone.style.borderColor = '';
            uploadZone.style.background = '';
        });

        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.style.borderColor = '';
            uploadZone.style.background = '';
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                showImagePreview(file);
            }
        });

        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) showImagePreview(file);
        });

        removeBtn.addEventListener('click', () => {
            preview.classList.add('hidden');
            uploadZone.classList.remove('hidden');
            fileInput.value = '';
        });

        function showImagePreview(file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                previewImg.src = e.target.result;
                preview.classList.remove('hidden');
                uploadZone.classList.add('hidden');
            };
            reader.readAsDataURL(file);
        }
    }

    // ============ SAMPLE MESSAGES ============
    function initSampleMessages() {
        document.querySelectorAll('.sample-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const sampleKey = this.dataset.sample;
                const sampleText = ScamDetector.sampleMessages[sampleKey];
                if (sampleText) {
                    document.getElementById('suspiciousText').value = sampleText;
                    document.getElementById('charCount').textContent = sampleText.length;

                    // Activate text tab
                    document.querySelectorAll('.input-tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.input-panel').forEach(p => p.classList.remove('active'));
                    document.querySelector('[data-tab="text-input"]').classList.add('active');
                    document.getElementById('text-input').classList.add('active');

                    speakText('Sample message loaded. Click Analyze Now to check it.');
                }
            });
        });
    }

    // ============ ANALYZE BUTTON ============
    function initAnalyzeButton() {
        document.getElementById('analyzeBtn').addEventListener('click', performAnalysis);

        document.getElementById('whatToDoBtn')?.addEventListener('click', () => {
            showWhatToDoModal();
        });
    }

    function performAnalysis() {
        // Get text from active input
        let text = '';
        let urlText = '';

        const activePanel = document.querySelector('.input-panel.active');
        if (activePanel.id === 'text-input') {
            text = document.getElementById('suspiciousText').value;
        } else if (activePanel.id === 'url-input') {
            urlText = document.getElementById('suspiciousUrl').value;
            text = urlText;
        } else {
            text = document.getElementById('suspiciousText').value;
        }

        if (!text || text.trim().length < 5) {
            alert('Please enter at least 5 characters to analyze.');
            return;
        }

        // Analyze
        let result;
        if (urlText) {
            const urlResult = URLAnalyzer.analyze(urlText);
            const textResult = ScamDetector.analyze(urlText, selectedIncidentType || 'other');

            // Merge results
            result = {
                ...textResult,
                score: Math.max(textResult.score, urlResult.score),
                level: getHigherLevel(textResult.level, urlResult.level),
                flags: [...textResult.flags, ...urlResult.flags.map(f => ({
                    ...f,
                    category: 'phishing',
                    categoryName: 'URL Analysis'
                }))]
            };
        } else {
            result = ScamDetector.analyze(text, selectedIncidentType || 'other');
        }

        lastResult = result;

        // Update dashboard
        Dashboard.addScan(result, text);

        // Display results
        displayResults(result);
    }

    function getHigherLevel(a, b) {
        const order = { high: 3, medium: 2, low: 1, insufficient: 0 };
        return (order[a] || 0) >= (order[b] || 0) ? a : b;
    }

    function displayResults(result) {
        const container = document.getElementById('resultsContainer');
        container.classList.remove('hidden');
        document.getElementById('step2').classList.add('hidden');

        // Risk Score Display
        const riskHtml = `
            <div class="risk-result ${result.level}">
                <div class="risk-score-circle">
                    <div class="risk-score-number">${result.score}</div>
                    <div class="risk-score-label">Risk Score</div>
                </div>
                <div class="risk-level">
                    ${result.level === 'high' ? '🚨 HIGH RISK' : result.level === 'medium' ? '⚠️ MEDIUM RISK' : '✅ LOW RISK'}
                </div>
                <div class="risk-category">
                    ${result.category ? `Likely Category: <strong>${result.category}</strong>` : 'No specific scam category identified'}
                </div>
                <div class="risk-disclaimer">
                    ⚠️ This is an automated awareness assessment and can make mistakes. A "low risk" score does NOT guarantee the message is genuine. Always verify independently.
                </div>
            </div>
        `;
        document.getElementById('riskResult').innerHTML = riskHtml;

        // Red Flags
        let flagsHtml = '<h3><i class="fas fa-flag" style="color: var(--danger);"></i> Red Flags Detected</h3>';
        if (result.flags.length > 0) {
            flagsHtml += result.flags.map((flag, i) => `
                <div class="red-flag-item ${flag.severity}-flag" style="animation-delay: ${i * 0.1}s">
                    <div class="red-flag-icon">
                        ${flag.severity === 'high' ? '🔴' : flag.severity === 'medium' ? '🟡' : '🔵'}
                    </div>
                    <div class="red-flag-content">
                        <h4>${flag.flag}</h4>
                        <p><strong>Why this is suspicious:</strong> ${flag.explanation}</p>
                        <p style="font-size:0.8rem; margin-top:4px; opacity:0.7;">Category: ${flag.categoryName || flag.category}</p>
                    </div>
                </div>
            `).join('');
        } else {
            flagsHtml += `
                <div class="red-flag-item low-flag">
                    <div class="red-flag-icon">ℹ️</div>
                    <div class="red-flag-content">
                        <h4>No major red flags detected</h4>
                        <p>The automated scan did not find known scam indicators. However, this does NOT mean the message is safe. New scam techniques may not be in our database. Always verify through official channels.</p>
                    </div>
                </div>
            `;
        }
        document.getElementById('redFlags').innerHTML = flagsHtml;

        // Immediate Actions
        let actionsHtml = '<h3><i class="fas fa-shield-alt" style="color: var(--success);"></i> Recommended Actions</h3>';
        actionsHtml += result.actions.map(action => `
            <div class="action-item">
                <div class="action-icon ${action.isDont ? 'dont' : ''}">
                    <i class="fas ${action.icon}"></i>
                </div>
                <div class="action-text">
                    <strong>${action.isDont ? '❌ ' : '✅ '}${action.title}</strong>
                    <p>${action.description}</p>
                </div>
            </div>
        `).join('');
        document.getElementById('immediateActions').innerHTML = actionsHtml;

        // Report Section (in results)
        let reportHtml = `
            <h3><i class="fas fa-exclamation-triangle" style="color: var(--warning);"></i> Reporting & Help</h3>
            <p style="margin-bottom:12px; font-size:0.9rem; color: var(--text-light);">These are verified official channels — independent of the risk analysis above.</p>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px;">
                <div style="padding:14px; background:var(--bg); border-radius:8px; text-align:center;">
                    <div style="font-size:1.8rem; font-weight:900; color:var(--danger);">1930</div>
                    <div style="font-size:0.85rem; font-weight:600;">Cyber Fraud Helpline</div>
                    <div style="font-size:0.75rem; color:var(--text-light);">Available 24/7</div>
                </div>
                <div style="padding:14px; background:var(--bg); border-radius:8px; text-align:center;">
                    <div style="font-size:1.1rem; font-weight:700; color:var(--primary);">cybercrime.gov.in</div>
                    <div style="font-size:0.85rem; font-weight:600;">Report Online</div>
                    <div style="font-size:0.75rem; color:var(--text-light);">File a complaint</div>
                </div>
                <div style="padding:14px; background:var(--bg); border-radius:8px; text-align:center;">
                    <div style="font-size:1.8rem; font-weight:900; color:var(--danger);">112</div>
                    <div style="font-size:0.85rem; font-weight:600;">Emergency Services</div>
                    <div style="font-size:0.75rem; color:var(--text-light);">For immediate threats</div>
                </div>
            </div>
        `;
        document.getElementById('reportActions').innerHTML = reportHtml;

        // Scroll to results
        container.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Read aloud
        if (readAloudMode) {
            const summary = `Risk score: ${result.score} out of 100. Risk level: ${result.level}. ${result.flags.length} red flags detected. ${result.category ? 'Likely scam category: ' + result.category : ''}`;
            speakText(summary);
        }
    }

    // ============ WHAT TO DO MODAL ============
    function showWhatToDoModal() {
        const modal = document.getElementById('actionModal');
        const body = document.getElementById('modalBody');

        let html = `
            <h2 style="margin-bottom:16px;"><i class="fas fa-hand-point-right"></i> What Should I Do Now?</h2>
        `;

        if (lastResult && lastResult.level === 'high') {
            html += `
                <div style="background:var(--danger-light); padding:16px; border-radius:8px; margin-bottom:16px; border-left:4px solid var(--danger);">
                    <h3 style="color:var(--danger);">⚠️ High Risk Detected</h3>
                    <p>This content has strong scam indicators. Take these steps:</p>
                </div>
                <ol style="padding-left:20px; margin-bottom:16px;">
                    <li style="margin-bottom:10px;"><strong>Do NOT respond</strong> to the message or call back.</li>
                    <li style="margin-bottom:10px;"><strong>Do NOT click any links</strong> or download attachments.</li>
                    <li style="margin-bottom:10px;"><strong>Do NOT share</strong> any personal information, OTP, or payment.</li>
                    <li style="margin-bottom:10px;"><strong>Block the sender</strong> on your phone/messaging app.</li>
                    <li style="margin-bottom:10px;"><strong>Take a screenshot</strong> for evidence before deleting.</li>
                    <li style="margin-bottom:10px;"><strong>Report</strong> to cybercrime.gov.in or call 1930.</li>
                    <li style="margin-bottom:10px;">If you already shared information or sent money, go to the <strong>Report</strong> section for immediate steps.</li>
                </ol>
            `;
        } else if (lastResult && lastResult.level === 'medium') {
            html += `
                <div style="background:var(--warning-light); padding:16px; border-radius:8px; margin-bottom:16px; border-left:4px solid var(--warning);">
                    <h3 style="color:#92400e;">⚡ Medium Risk — Proceed with Caution</h3>
                    <p>Some suspicious indicators were found. Verify before taking action.</p>
                </div>
                <ol style="padding-left:20px; margin-bottom:16px;">
                    <li style="margin-bottom:10px;"><strong>Do NOT act on the message immediately.</strong> Take time to think.</li>
                    <li style="margin-bottom:10px;"><strong>Independently verify</strong> — search for the organization's official website and contact them directly.</li>
                    <li style="margin-bottom:10px;">If it claims to be from your bank, <strong>call the number on your card</strong>, not the number in the message.</li>
                    <li style="margin-bottom:10px;"><strong>Do not click links.</strong> Type the official URL directly in your browser.</li>
                    <li style="margin-bottom:10px;">When in doubt, <strong>ask a trusted friend or family member</strong> for a second opinion.</li>
                </ol>
            `;
        } else {
            html += `
                <div style="background:var(--success-light); padding:16px; border-radius:8px; margin-bottom:16px; border-left:4px solid var(--success);">
                    <h3 style="color:#166534;">✅ Low Risk — But Stay Vigilant</h3>
                    <p>No major red flags were found, but remember that our detector cannot catch every scam.</p>
                </div>
                <ul style="padding-left:20px; margin-bottom:16px;">
                    <li style="margin-bottom:10px;">A low-risk score does <strong>NOT guarantee</strong> the message is genuine.</li>
                    <li style="margin-bottom:10px;"><strong>Still verify independently</strong> if the message asks for any action, payment, or information.</li>
                    <li style="margin-bottom:10px;">New scam techniques may not be in our database.</li>
                    <li style="margin-bottom:10px;">Trust your instincts — if something feels off, it probably is.</li>
                </ul>
            `;
        }

        html += `
            <div style="background:var(--bg); padding:14px; border-radius:8px; margin-top:12px;">
                <p style="font-size:0.85rem; text-align:center; color: var(--text-light);">
                    <i class="fas fa-info-circle"></i> Need more help? Go to the 
                    <a href="#report" onclick="closeModal(); showSection('report');" style="color:var(--primary); font-weight:600;">Report & Get Help</a> section 
                    for official reporting channels and the incident response guide.
                </p>
            </div>
        `;

        body.innerHTML = html;
        modal.classList.remove('hidden');
    }

    // ============ COMPARE ============
    function initCompare() {
        document.getElementById('compareBtn').addEventListener('click', performComparison);
        document.getElementById('loadCompareDemo').addEventListener('click', loadCompareDemos);
    }

    function performComparison() {
        const textA = document.getElementById('compareA').value;
        const textB = document.getElementById('compareB').value;

        if (!textA.trim() || !textB.trim()) {
            alert('Please enter text in both panels to compare.');
            return;
        }

        const resultA = ScamDetector.analyze(textA, 'other');
        const resultB = ScamDetector.analyze(textB, 'other');

        // Display results for A
        displayCompareResult('compareResultA', resultA);
        displayCompareResult('compareResultB', resultB);

        // Verdict
        const verdict = document.getElementById('compareVerdict');
        verdict.classList.remove('hidden');

        let verdictText = '';
        if (resultA.score > resultB.score) {
            verdictText = `<h3>📊 Comparison Result</h3>
                <p><strong>Message A</strong> is more suspicious (score: ${resultA.score}) compared to <strong>Message B</strong> (score: ${resultB.score}).</p>
                <p style="margin-top:8px; color:var(--text-light);">Message A has ${resultA.flags.length} red flag(s) vs Message B's ${resultB.flags.length} red flag(s).</p>`;
        } else if (resultB.score > resultA.score) {
            verdictText = `<h3>📊 Comparison Result</h3>
                <p><strong>Message B</strong> is more suspicious (score: ${resultB.score}) compared to <strong>Message A</strong> (score: ${resultA.score}).</p>
                <p style="margin-top:8px; color:var(--text-light);">Message B has ${resultB.flags.length} red flag(s) vs Message A's ${resultA.flags.length} red flag(s).</p>`;
        } else {
            verdictText = `<h3>📊 Comparison Result</h3>
                <p>Both messages have similar risk scores (${resultA.score} and ${resultB.score}). Review the individual red flags above for differences.</p>`;
        }

        verdictText += `<p style="margin-top:12px; font-size:0.85rem; color:var(--text-light);"><i class="fas fa-info-circle"></i> Remember: This is an automated assessment and can make mistakes.</p>`;
        verdict.innerHTML = verdictText;
    }

    function displayCompareResult(containerId, result) {
        const container = document.getElementById(containerId);
        container.innerHTML = `
            <div style="padding:12px; border-radius:8px; text-align:center; background:${result.level === 'high' ? 'var(--danger-light)' : result.level === 'medium' ? 'var(--warning-light)' : 'var(--success-light)'};">
                <div style="font-size:1.8rem; font-weight:800;">${result.score}</div>
                <div style="font-size:0.85rem; font-weight:600; text-transform:uppercase;">
                    ${result.level === 'high' ? '🚨 High Risk' : result.level === 'medium' ? '⚠️ Medium Risk' : '✅ Low Risk'}
                </div>
                ${result.category ? `<div style="font-size:0.8rem; color:var(--text-light); margin-top:4px;">${result.category}</div>` : ''}
                <div style="margin-top:8px; font-size:0.8rem;">${result.flags.length} red flag(s) found</div>
            </div>
            ${result.flags.length > 0 ? `
                <div style="margin-top:10px;">
                    ${result.flags.slice(0, 4).map(f => `
                        <div style="font-size:0.8rem; padding:6px 8px; background:var(--bg); border-radius:4px; margin-bottom:4px; display:flex; gap:6px; align-items:center;">
                            ${f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟡' : '🔵'} ${f.flag}
                        </div>
                    `).join('')}
                    ${result.flags.length > 4 ? `<div style="font-size:0.75rem; color:var(--text-light); text-align:center;">+ ${result.flags.length - 4} more</div>` : ''}
                </div>
            ` : ''}
        `;
    }

    function loadCompareDemos() {
        document.getElementById('compareA').value = ScamDetector.sampleMessages.bank;
        document.getElementById('compareB').value = ScamDetector.sampleMessages.legitimate;
        speakText('Demo messages loaded. Click Compare Now to analyze.');
    }

    // ============ QUIZ ============
    const quizQuestions = [
        {
            question: 'You receive an SMS: "Your SBI account will be blocked in 2 hours. Update KYC now: http://sbi-update.tk/kyc". What should you do?',
            options: [
                'Click the link and update KYC quickly',
                'Call the number mentioned in the SMS',
                'Ignore the link, call SBI using the number on your card/official website',
                'Forward the message to 10 friends as a warning'
            ],
            correct: 2,
            explanation: 'Never click links in such messages. Banks send KYC notices through their official app and branches. Always call using the number from your card or the bank\'s official website — never from the message itself.'
        },
        {
            question: 'A caller says they are from "Cyber Crime Department" and says a case is filed against your Aadhaar. They ask you to install AnyDesk to "resolve the issue." What is this?',
            options: [
                'A legitimate investigation — cooperate fully',
                'A scam — real police don\'t call and ask you to install apps',
                'Probably real since they know your name',
                'You should install the app just to check'
            ],
            correct: 1,
            explanation: 'This is a scam. Real law enforcement serves official notices — they don\'t call and ask you to install remote access apps. AnyDesk/TeamViewer gives them complete control of your phone, including access to banking apps.'
        },
        {
            question: 'You see a WhatsApp message: "Earn ₹50,000 daily from home! No experience needed! Just pay ₹2,000 registration fee." What red flags can you identify?',
            options: [
                'Only the high earning claim is suspicious',
                'Unrealistic income promise + upfront payment required + no qualifications needed — multiple red flags',
                'It seems legitimate since many work-from-home jobs exist',
                'The registration fee is reasonable for a good-paying job'
            ],
            correct: 1,
            explanation: 'This has MULTIPLE red flags: unrealistic guaranteed income (₹50,000/day), no skills/experience required, and an upfront fee. Legitimate employers never charge candidates. This is a classic job scam.'
        },
        {
            question: 'You receive a UPI collect request claiming to be a "refund" from Flipkart. What should you know?',
            options: [
                'Accept it — refunds come as collect requests',
                'Decline — you NEVER need to approve/pay to RECEIVE money via UPI',
                'Enter your PIN to check if it\'s real',
                'Accept it if the amount matches your order'
            ],
            correct: 1,
            explanation: 'You NEVER need to enter your UPI PIN or approve a collect request to receive money. Refunds are directly credited to your account. A "collect request" asking for PIN approval is always a payment FROM you, not TO you.'
        },
        {
            question: 'Which of these URLs is most likely a phishing attempt?',
            options: [
                'https://www.amazon.in/orders',
                'http://amaz0n-deals.xyz/login',
                'https://pay.google.com',
                'https://www.flipkart.com/account'
            ],
            correct: 1,
            explanation: '"amaz0n-deals.xyz" has three red flags: the "o" is replaced with "0" (typosquatting), it uses a suspicious .xyz domain, and it uses HTTP instead of HTTPS. Always check URLs carefully for misspellings and unusual domains.'
        }
    ];

    function initQuiz() {
        document.getElementById('startQuizBtn').addEventListener('click', startQuiz);
        document.getElementById('nextQuizBtn').addEventListener('click', nextQuestion);
    }

    function startQuiz() {
        currentQuizIndex = 0;
        quizScore = 0;
        document.getElementById('startQuizBtn').style.display = 'none';
        showQuizQuestion();
    }

    function showQuizQuestion() {
        if (currentQuizIndex >= quizQuestions.length) {
            showQuizResult();
            return;
        }

        const q = quizQuestions[currentQuizIndex];
        document.getElementById('quizQuestion').innerHTML = `
            <p style="font-size:0.85rem; color:var(--text-light); margin-bottom:8px;">Question ${currentQuizIndex + 1} of ${quizQuestions.length}</p>
            <p style="font-weight:600;">${q.question}</p>
        `;

        document.getElementById('quizOptions').innerHTML = q.options.map((opt, i) => `
            <button class="quiz-option" onclick="handleQuizAnswer(${i})">${opt}</button>
        `).join('');

        document.getElementById('quizFeedback').classList.add('hidden');
        document.getElementById('nextQuizBtn').style.display = 'none';

        speakText(q.question);
    }

    window.handleQuizAnswer = function(index) {
        const q = quizQuestions[currentQuizIndex];
        const options = document.querySelectorAll('.quiz-option');
        const feedback = document.getElementById('quizFeedback');

        // Disable all options
        options.forEach((opt, i) => {
            opt.style.pointerEvents = 'none';
            if (i === q.correct) opt.classList.add('correct');
            if (i === index && i !== q.correct) opt.classList.add('incorrect');
        });

        if (index === q.correct) {
            quizScore++;
            feedback.className = 'quiz-feedback correct-feedback';
            feedback.innerHTML = `<strong>✅ Correct!</strong> ${q.explanation}`;
        } else {
            feedback.className = 'quiz-feedback incorrect-feedback';
            feedback.innerHTML = `<strong>❌ Incorrect.</strong> ${q.explanation}`;
        }

        feedback.classList.remove('hidden');
        document.getElementById('nextQuizBtn').style.display = 'inline-flex';

        speakText(index === q.correct ? 'Correct!' : 'Incorrect.');
    };

    function nextQuestion() {
        currentQuizIndex++;
        showQuizQuestion();
    }

    function showQuizResult() {
        const container = document.getElementById('quizContainer');
        const percentage = Math.round((quizScore / quizQuestions.length) * 100);

        container.innerHTML = `
            <div style="text-align:center; padding:24px;">
                <div style="font-size:3rem; margin-bottom:12px;">${percentage >= 80 ? '🏆' : percentage >= 60 ? '👍' : '📚'}</div>
                <h3>Quiz Complete!</h3>
                <p style="font-size:1.5rem; font-weight:800; margin:12px 0;">${quizScore} / ${quizQuestions.length}</p>
                <p style="color:var(--text-light);">
                    ${percentage >= 80 ? 'Excellent! You have strong scam awareness skills.' :
                      percentage >= 60 ? 'Good job! Review the explanations to strengthen your knowledge.' :
                      'Keep learning! Check the Learn section for more about scam tactics.'}
                </p>
                <button class="btn-primary" onclick="location.reload()" style="margin-top:16px;">
                    <i class="fas fa-redo"></i> Try Again
                </button>
            </div>
        `;
    }

    // ============ ACCESSIBILITY ============
    function initAccessibility() {
        // Dark Mode
        document.getElementById('darkModeToggle').addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            this.classList.toggle('active');
            const icon = this.querySelector('i');
            icon.className = document.body.classList.contains('dark-mode') ? 'fas fa-sun' : 'fas fa-moon';
        });

        // Large Text
        document.getElementById('fontSizeToggle').addEventListener('click', function() {
            document.body.classList.toggle('large-text');
            this.classList.toggle('active');
        });

        // Read Aloud
        document.getElementById('readAloudToggle').addEventListener('click', function() {
            readAloudMode = !readAloudMode;
            this.classList.toggle('active');
            document.getElementById('readAloudIndicator').classList.toggle('hidden', !readAloudMode);
            if (readAloudMode) {
                speakText('Read aloud mode activated. Important text will be read out loud.');
            } else {
                window.speechSynthesis?.cancel();
            }
        });
    }

    // ============ SPEECH ============
    function speakText(text) {
        if (!readAloudMode || !window.speechSynthesis) return;
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 0.9;
        utterance.pitch = 1;
        utterance.lang = 'en-IN';
        window.speechSynthesis.speak(utterance);
    }

    // ============ GLOBAL FUNCTIONS ============
    window.goToStep = function(step) {
        document.getElementById('step1').classList.toggle('hidden', step !== 1);
        document.getElementById('step2').classList.toggle('hidden', step !== 2);
        document.getElementById('resultsContainer').classList.add('hidden');

        const target = step === 1 ? document.getElementById('step1') : document.getElementById('step2');
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    window.resetAnalyzer = function() {
        document.getElementById('resultsContainer').classList.add('hidden');
        document.getElementById('step2').classList.remove('hidden');
        document.getElementById('suspiciousText').value = '';
        document.getElementById('suspiciousUrl').value = '';
        document.getElementById('charCount').textContent = '0';
        lastResult = null;
        document.getElementById('step2').scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    window.closeModal = function() {
        document.getElementById('actionModal').classList.add('hidden');
    };

    window.closeBanner = function() {
        document.getElementById('disclaimer-banner').style.display = 'none';
    };

    window.showSection = showSection;
    window.speakText = speakText;

})();
