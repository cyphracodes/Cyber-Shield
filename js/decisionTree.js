/**
 * CYBER SHIELD — Incident Decision Tree
 * Provides response guidance based on what happened.
 */

const DecisionTree = (() => {
    const nodes = {
        'money-lost': {
            title: '💰 You Sent Money / Made a Payment',
            steps: [
                '<strong>Act within minutes if possible.</strong> Speed is critical for financial fraud recovery.',
                '<strong>Call your bank IMMEDIATELY</strong> using the number on the BACK of your card or from the official website. Request them to freeze/reverse the transaction.',
                '<strong>Call 1930</strong> (National Cyber Fraud Helpline). They coordinate with banks for quick freezing of funds.',
                '<strong>DO NOT make any more payments</strong> — scammers often ask for additional "processing fees" or "refund charges."',
                '<strong>File an online complaint</strong> at cybercrime.gov.in with all transaction details.',
                '<strong>File an FIR</strong> at your nearest police station. Carry all evidence.',
                '<strong>Document everything:</strong> Screenshots of messages, transaction IDs, UPI reference numbers, phone numbers, call logs.'
            ],
            urgency: 'CRITICAL',
            followUp: 'How was the money sent?',
            subOptions: [
                { label: 'UPI / Google Pay / PhonePe', answer: 'Contact the UPI app\'s support immediately. In the app, go to the transaction and raise a dispute. Also contact your bank. Report on NPCI portal if needed.' },
                { label: 'Bank Transfer / NEFT / IMPS', answer: 'Call your bank\'s fraud helpline immediately. Request a "lien" on the beneficiary account. File complaint with both sender and receiver banks.' },
                { label: 'Credit / Debit Card', answer: 'Call your card issuer immediately to block the card and dispute the charge. Most cards have fraud protection — the sooner you report, the better your chances of reversal.' },
                { label: 'Cash / Gift Cards / Crypto', answer: 'Unfortunately, cash and cryptocurrency transactions are very difficult to reverse. File an FIR and report to cybercrime.gov.in. For gift cards, contact the issuing company immediately.' }
            ]
        },
        'creds-shared': {
            title: '🔑 You Shared Passwords / OTP / PIN',
            steps: [
                '<strong>Change ALL affected passwords IMMEDIATELY</strong> from a secure device.',
                '<strong>Enable Two-Factor Authentication (2FA)</strong> on all accounts that support it.',
                '<strong>If banking credentials were shared:</strong> Call your bank NOW to block your account temporarily and reset credentials.',
                '<strong>Check for unauthorized transactions</strong> in all linked accounts.',
                '<strong>Log out of all sessions</strong> — most services have a "Sign out everywhere" option in security settings.',
                '<strong>If email password was shared:</strong> Check for email forwarding rules that scammers may have set up to intercept your emails.',
                '<strong>Monitor your accounts</strong> closely for the next 30-60 days for any suspicious activity.'
            ],
            urgency: 'HIGH'
        },
        'app-installed': {
            title: '📱 You Installed an Unknown App',
            steps: [
                '<strong>Disconnect from the internet</strong> — Turn off WiFi and mobile data immediately to prevent data theft.',
                '<strong>DO NOT open</strong> any banking or financial apps.',
                '<strong>Uninstall the suspicious app</strong> immediately from Settings > Apps.',
                '<strong>Run a security scan</strong> with a trusted antivirus app (e.g., Google Play Protect).',
                '<strong>Change passwords</strong> for all accounts from a DIFFERENT, secure device.',
                '<strong>If the app was a remote access tool</strong> (AnyDesk, TeamViewer, etc.): Assume the scammer saw everything on your screen. Change ALL passwords and call your bank.',
                '<strong>Consider a factory reset</strong> if you suspect malware, but backup important data first.',
                '<strong>Check your phone bill</strong> for unauthorized premium SMS or subscriptions.'
            ],
            urgency: 'HIGH'
        },
        'info-shared': {
            title: '📋 You Shared Personal Information',
            steps: [
                '<strong>Assess what was shared:</strong> Name and phone number are less risky than Aadhaar, PAN, or bank details.',
                '<strong>If Aadhaar was shared:</strong> Lock your Aadhaar biometrics at resident.uidai.gov.in. This prevents misuse for authentication.',
                '<strong>If PAN was shared:</strong> Monitor your credit report on CIBIL for any unauthorized loans or credit applications.',
                '<strong>Set up fraud alerts</strong> with credit bureaus (CIBIL, Experian, Equifax).',
                '<strong>Be extra cautious</strong> of follow-up scams — scammers may use your information to create more convincing attacks.',
                '<strong>Do NOT share any additional information</strong> if the scammer contacts you again.',
                '<strong>Report to cybercrime.gov.in</strong> if you believe your identity may be misused.'
            ],
            urgency: 'MEDIUM'
        },
        'nothing-yet': {
            title: '✋ You Haven\'t Done Anything Yet — Good!',
            steps: [
                '<strong>Well done!</strong> Being cautious is the best defense.',
                '<strong>Do not respond</strong> to the suspicious message or call.',
                '<strong>Do not click any links</strong> — not even to "see what happens."',
                '<strong>Block the sender</strong> on your phone and messaging apps.',
                '<strong>Report the message:</strong> In WhatsApp, long-press > Report. For SMS, forward to your carrier\'s spam number.',
                '<strong>If curious about legitimacy,</strong> independently search for the organization\'s official website and contact them directly.',
                '<strong>Warn others</strong> — let family and friends know about the scam so they don\'t fall for it.',
                '<strong>Report at cybercrime.gov.in</strong> to help authorities track scam patterns.'
            ],
            urgency: 'LOW'
        }
    };

    function getNode(nodeId) {
        return nodes[nodeId] || null;
    }

    function renderNode(nodeId, container) {
        const node = nodes[nodeId];
        if (!node) return;

        let html = `
            <div class="dt-answer">
                <h4>${node.title}</h4>
                ${node.urgency ? `<p style="margin-bottom:12px;"><strong>Urgency Level: 
                    <span style="color:${node.urgency === 'CRITICAL' ? '#dc2626' : node.urgency === 'HIGH' ? '#f59e0b' : node.urgency === 'MEDIUM' ? '#2563eb' : '#16a34a'}">
                    ${node.urgency}</span></strong></p>` : ''}
                <ol>
                    ${node.steps.map(step => `<li>${step}</li>`).join('')}
                </ol>
        `;

        if (node.subOptions) {
            html += `<p style="margin-top:12px; font-weight:600;">${node.followUp}</p>
                <div class="dt-options" style="margin-top:8px;">
                    ${node.subOptions.map((opt, i) => 
                        `<button class="dt-btn dt-sub-btn" data-subindex="${i}" onclick="DecisionTree.showSubAnswer(this, ${i}, '${nodeId}')">
                            ${opt.label}
                        </button>`
                    ).join('')}
                </div>
                <div id="subAnswer-${nodeId}" style="margin-top:12px;"></div>
            `;
        }

        html += `<button class="dt-back" onclick="DecisionTree.reset()"><i class="fas fa-arrow-left"></i> Back to questions</button>`;
        html += `</div>`;

        container.innerHTML = `<div class="dt-question"><p>${document.querySelector('#dtStart p').textContent}</p></div>` + html;
    }

    function showSubAnswer(btn, index, nodeId) {
        const node = nodes[nodeId];
        if (!node || !node.subOptions[index]) return;

        const container = document.getElementById(`subAnswer-${nodeId}`);
        container.innerHTML = `
            <div style="background: var(--warning-light); padding: 14px; border-radius: 8px; border-left: 4px solid var(--warning); margin-top: 8px;">
                <p><strong>${node.subOptions[index].label}:</strong></p>
                <p style="margin-top:6px; font-size:0.9rem;">${node.subOptions[index].answer}</p>
            </div>
        `;

        // Remove active from all sub buttons
        document.querySelectorAll('.dt-sub-btn').forEach(b => b.style.borderColor = '');
        btn.style.borderColor = 'var(--primary)';
    }

    function reset() {
        const container = document.getElementById('decisionTree');
        container.innerHTML = `
            <div class="dt-question" id="dtStart">
                <p>What best describes your situation?</p>
                <div class="dt-options">
                    <button class="dt-btn" data-next="money-lost"><i class="fas fa-money-bill-wave"></i> I sent money / made a payment</button>
                    <button class="dt-btn" data-next="creds-shared"><i class="fas fa-key"></i> I shared passwords / OTP / PIN</button>
                    <button class="dt-btn" data-next="app-installed"><i class="fas fa-mobile-alt"></i> I installed an unknown app</button>
                    <button class="dt-btn" data-next="info-shared"><i class="fas fa-id-card"></i> I shared personal information</button>
                    <button class="dt-btn" data-next="nothing-yet"><i class="fas fa-hand-paper"></i> I haven't done anything yet</button>
                </div>
            </div>
        `;
        initDecisionTree();
    }

    function initDecisionTree() {
        document.querySelectorAll('.dt-btn[data-next]').forEach(btn => {
            btn.addEventListener('click', function() {
                const nodeId = this.dataset.next;
                const container = document.getElementById('decisionTree');
                renderNode(nodeId, container);
            });
        });
    }

    return {
        getNode,
        renderNode,
        showSubAnswer,
        reset,
        init: initDecisionTree
    };
})();
