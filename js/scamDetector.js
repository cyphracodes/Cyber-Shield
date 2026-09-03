/**
 * CYBER SHIELD — Rule-Based Scam Detector Engine
 * Matches known scam indicators and assigns a risk score.
 */

const ScamDetector = (() => {
    // Scam indicator rules with weights, categories, and explanations
    const rules = [
        // URGENCY
        {
            id: 'urgency_time',
            pattern: /\b(urgent|immediately|right now|within \d+ (minutes?|hours?)|act fast|act now|hurry|last chance|limited time|expires? (today|soon|in \d+)|time.?sensitive|don'?t delay|before it'?s too late)\b/i,
            weight: 15,
            category: 'urgency',
            severity: 'high',
            flag: 'Artificial Urgency',
            explanation: 'The message creates fake time pressure to prevent you from thinking clearly or verifying. Legitimate organizations give you reasonable time to respond.'
        },
        {
            id: 'urgency_deadline',
            pattern: /\b(deadline|final notice|final warning|last reminder|account.*(block|suspend|close|terminat|deactivat))\b/i,
            weight: 14,
            category: 'urgency',
            severity: 'high',
            flag: 'Threat of Account Action',
            explanation: 'Threatening to block or suspend your account creates panic. Real banks and services send multiple official notices through verified channels, not just SMS or WhatsApp.'
        },

        // FINANCIAL DEMANDS
        {
            id: 'payment_demand',
            pattern: /\b(send money|transfer.*(amount|fund|money|₹|\$)|pay (now|immediately|urgently)|processing fee|registration fee|advance (fee|payment)|pay.*to (claim|receive|unlock))\b/i,
            weight: 20,
            category: 'financial_fraud',
            severity: 'high',
            flag: 'Payment Demand',
            explanation: 'Asking you to send money upfront is a classic scam tactic. Legitimate prizes, jobs, or services do not require you to pay money to receive benefits.'
        },
        {
            id: 'upi_request',
            pattern: /\b(upi|google ?pay|phone ?pe|paytm|bhim).*(send|transfer|pay|request|collect)/i,
            weight: 16,
            category: 'financial_fraud',
            severity: 'high',
            flag: 'UPI Payment Request',
            explanation: 'Scammers often send UPI collect requests disguised as refunds or prizes. Remember: you never need to enter your PIN or approve a request to RECEIVE money.'
        },
        {
            id: 'crypto_payment',
            pattern: /\b(bitcoin|crypto|wallet address|btc|ethereum|usdt)\b/i,
            weight: 12,
            category: 'financial_fraud',
            severity: 'medium',
            flag: 'Cryptocurrency Payment Mentioned',
            explanation: 'Cryptocurrency payments are irreversible and untraceable. Scammers prefer crypto because victims cannot recover funds once sent.'
        },

        // CREDENTIAL REQUESTS
        {
            id: 'otp_request',
            pattern: /\b(otp|one.?time.?password|verification code|share.*(code|otp)|send.*(code|otp)|enter.*(otp|code))\b/i,
            weight: 22,
            category: 'credential_theft',
            severity: 'high',
            flag: 'OTP / Verification Code Request',
            explanation: 'No legitimate organization will ask you to share your OTP. An OTP is your private security key — sharing it gives complete access to your account.'
        },
        {
            id: 'password_request',
            pattern: /\b(password|passcode|pin|cvv|card.?number|account.?number|credit.?card|debit.?card|bank.?details|login.?credentials|security.?code)\b/i,
            weight: 20,
            category: 'credential_theft',
            severity: 'high',
            flag: 'Sensitive Credentials Requested',
            explanation: 'Banks and genuine services NEVER ask for your password, PIN, CVV, or card number via message, call, or email. This is an attempt to steal your financial information.'
        },
        {
            id: 'aadhaar_pan',
            pattern: /\b(aadhaar|aadhar|pan.?(card|number)|voter.?id|passport.?number|identity.?proof)\b/i,
            weight: 14,
            category: 'identity_theft',
            severity: 'medium',
            flag: 'Identity Document Request',
            explanation: 'Requesting Aadhaar, PAN, or ID numbers through unofficial channels could lead to identity theft. Only share such details through verified official portals.'
        },

        // KYC SCAM
        {
            id: 'kyc_update',
            pattern: /\b(kyc.*(update|verify|expire|pending|complete|mandatory)|update.?kyc|verify.?kyc|kyc.*(link|form))\b/i,
            weight: 18,
            category: 'phishing',
            severity: 'high',
            flag: 'Fake KYC Update Request',
            explanation: 'KYC update scams are extremely common. Banks do require KYC but they direct you through their official app or branch — never through links in SMS or WhatsApp messages.'
        },

        // PRIZES & REWARDS
        {
            id: 'prize_won',
            pattern: /\b(won|winner|congratulat|you.?have.?been.?selected|lucky.?draw|lucky.?winner|prize|reward|jackpot|lottery|lott[eo]ry|claim.?your|cash.?prize)\b/i,
            weight: 18,
            category: 'prize_scam',
            severity: 'high',
            flag: 'Fake Prize / Lottery Win',
            explanation: 'You cannot win a contest you never entered. Prize scams lure you with excitement and then ask for "processing fees" or personal information to claim your non-existent winnings.'
        },
        {
            id: 'free_gift',
            pattern: /\b(free (gift|iphone|phone|laptop|voucher|offer)|gift.?card|amazon.?voucher|flipkart.?voucher|cashback.*guaranteed)\b/i,
            weight: 14,
            category: 'prize_scam',
            severity: 'medium',
            flag: 'Too-Good-To-Be-True Free Offer',
            explanation: 'Free expensive items are used as bait. The real goal is to collect your personal information, install malware, or extract payment for "shipping" or "taxes."'
        },

        // JOB SCAMS
        {
            id: 'job_offer',
            pattern: /\b(work.?from.?home|earn.?(\₹|rs|money).*per.?(day|hour|month)|part.?time.?(job|income|earn)|data.?entry.?job|typing.?job|online.?job.*no.?experience|guaranteed.?(income|salary|earn))\b/i,
            weight: 16,
            category: 'job_scam',
            severity: 'high',
            flag: 'Suspicious Job Offer',
            explanation: 'Job scams promise unrealistic income for simple tasks. Real jobs have proper interviews and contracts. Be very suspicious of jobs asking for upfront fees or offering guaranteed high income.'
        },
        {
            id: 'job_fee',
            pattern: /\b(registration.?(fee|charge)|joining.?fee|security.?deposit|training.?fee).*job/i,
            weight: 18,
            category: 'job_scam',
            severity: 'high',
            flag: 'Job Requiring Payment',
            explanation: 'Legitimate employers never ask candidates to pay money for a job. Any "fee" for registration, training, or security deposit for a job offer is a scam.'
        },

        // INVESTMENT SCAMS
        {
            id: 'guaranteed_return',
            pattern: /\b(guaranteed.?return|100%.?profit|double.?your.?money|risk.?free.?investment|high.?return|fixed.?return.?of.*%|earn.*%.*daily|daily.?(profit|return|income))\b/i,
            weight: 20,
            category: 'investment_scam',
            severity: 'high',
            flag: 'Guaranteed Returns Promise',
            explanation: 'No legitimate investment can guarantee returns. Promises of guaranteed high returns are the hallmark of Ponzi schemes and investment fraud. Even banks cannot guarantee fixed returns on investments.'
        },
        {
            id: 'invest_now',
            pattern: /\b(invest.?now|trading.?(signal|tip)|stock.?tip|forex|binary.?option|mutual.?fund.*(guaranteed|assured))\b/i,
            weight: 14,
            category: 'investment_scam',
            severity: 'medium',
            flag: 'Unsolicited Investment Advice',
            explanation: 'Unsolicited investment tips from unknown sources are often pump-and-dump schemes. Always consult SEBI-registered advisors and verify through official financial channels.'
        },

        // IMPERSONATION
        {
            id: 'authority_impersonation',
            pattern: /\b(this is.*(police|cyber.?cell|rbi|income.?tax|customs|government|officer|inspector|cbi|ed|enforcement))|from.*(police|rbi|government|ministry|department)/i,
            weight: 16,
            category: 'impersonation',
            severity: 'high',
            flag: 'Authority Impersonation',
            explanation: 'Scammers claim to be police, RBI, tax officers, or government officials to intimidate you. Real authorities do not call to threaten arrest or demand immediate payment over the phone.'
        },
        {
            id: 'bank_impersonation',
            pattern: /\b(dear.?customer|valued.?customer|your.?bank|bank.?manager|team.?(sbi|hdfc|icici|axis|kotak|pnb|bob))\b/i,
            weight: 12,
            category: 'impersonation',
            severity: 'medium',
            flag: 'Bank Impersonation',
            explanation: 'Generic greetings like "Dear Customer" are a red flag. Your real bank uses your name and account details (partially masked). Verify by calling the number on your card.'
        },

        // SUSPICIOUS LINKS
        {
            id: 'shortened_url',
            pattern: /(bit\.ly|tinyurl|goo\.gl|t\.co|short\.link|is\.gd|buff\.ly|ow\.ly|rb\.gy|cutt\.ly|shorturl)/i,
            weight: 14,
            category: 'phishing',
            severity: 'medium',
            flag: 'Shortened URL Detected',
            explanation: 'URL shorteners hide the real destination. Scammers use them to disguise malicious links. Never click shortened URLs from unknown senders.'
        },
        {
            id: 'suspicious_url',
            pattern: /https?:\/\/[^\s]*[^\s.](\.xyz|\.tk|\.ml|\.ga|\.cf|\.gq|\.top|\.click|\.buzz|\.club|\.icu|\.work|\.site|\.online|\.live|\.store)/i,
            weight: 14,
            category: 'phishing',
            severity: 'medium',
            flag: 'Suspicious Domain Extension',
            explanation: 'Domains ending in .xyz, .tk, .click, .buzz and similar free/cheap extensions are frequently used by scammers because they are easy and inexpensive to register anonymously.'
        },
        {
            id: 'lookalike_domain',
            pattern: /(g00gle|amaz0n|faceb00k|paypa1|paypai|micr0soft|app1e|netfl1x|flipk[a@]rt|am[a@]zon|go0gle|whatsap|instag[r@]am)/i,
            weight: 18,
            category: 'phishing',
            severity: 'high',
            flag: 'Look-alike / Typosquatting Domain',
            explanation: 'The URL mimics a well-known brand by replacing letters with numbers or adding subtle misspellings. This is called "typosquatting" — designed to trick you into thinking it\'s the real website.'
        },
        {
            id: 'click_link',
            pattern: /\b(click (here|below|this)|open (this|the) link|visit.*link|tap (here|to open)|download.*link)\b/i,
            weight: 10,
            category: 'phishing',
            severity: 'medium',
            flag: 'Pressing to Click a Link',
            explanation: 'Messages urging you to click a link immediately are often phishing attempts. Instead of clicking, navigate to the official website by typing the address yourself.'
        },

        // APP INSTALLATION
        {
            id: 'apk_download',
            pattern: /\.(apk|exe)\b|install.*(app|software|update)|download.*app|sideload/i,
            weight: 18,
            category: 'malware',
            severity: 'high',
            flag: 'Unknown App / APK Installation',
            explanation: 'Installing apps from links in messages (especially .apk files) can install malware that steals data, records your screen, or takes control of your device. Only install apps from official app stores.'
        },
        {
            id: 'remote_access',
            pattern: /\b(teamviewer|anydesk|quicksupport|screen.?share|remote.?access|desktop.?share)\b/i,
            weight: 20,
            category: 'malware',
            severity: 'high',
            flag: 'Remote Access App Request',
            explanation: 'Scammers ask you to install remote access apps to take control of your phone or computer. Once installed, they can see your screen, access your banking apps, and transfer your money.'
        },

        // EMOTIONAL MANIPULATION
        {
            id: 'fear_threat',
            pattern: /\b(legal.?action|arrest|fir|case.?filed|police.?complaint|court.?notice|warrant|jail|prosecution|penalty|fine of|blocked.?permanently)\b/i,
            weight: 16,
            category: 'threat_intimidation',
            severity: 'high',
            flag: 'Fear & Threat Tactics',
            explanation: 'Threats of arrest, legal action, or fines are used to create panic. Real law enforcement sends official documents — they don\'t threaten via phone calls, SMS, or WhatsApp.'
        },

        // GRAMMAR & PRESENTATION
        {
            id: 'excessive_caps',
            pattern: /[A-Z]{5,}/,
            weight: 6,
            category: 'presentation',
            severity: 'low',
            flag: 'Excessive Capitalization',
            explanation: 'Excessive use of CAPITAL LETTERS is a common tactic to convey fake urgency and grab attention. Professional organizations use proper formatting.'
        },
        {
            id: 'excessive_exclamation',
            pattern: /!{2,}|!.*!.*!/,
            weight: 5,
            category: 'presentation',
            severity: 'low',
            flag: 'Excessive Exclamation Marks',
            explanation: 'Multiple exclamation marks (!!!) are used to create artificial excitement or urgency. Professional communications use measured punctuation.'
        },
        {
            id: 'money_emoji',
            pattern: /[💰💵💳🏦🎰🎁🎉🤑💸🏧💎]+/u,
            weight: 5,
            category: 'presentation',
            severity: 'low',
            flag: 'Money / Gift Emojis',
            explanation: 'Excessive money and gift emojis are used to trigger excitement and greed. Legitimate organizations communicate professionally without emoji-laden messages.'
        },

        // GENERIC GREETING
        {
            id: 'generic_greeting',
            pattern: /\b(dear (sir|madam|customer|user|friend|member|citizen)|hello user|respected sir|attn:)\b/i,
            weight: 8,
            category: 'impersonation',
            severity: 'low',
            flag: 'Generic Greeting',
            explanation: 'Legitimate organizations typically address you by name. Generic greetings like "Dear Customer" or "Dear Sir/Madam" suggest a mass message sent to many potential victims.'
        },

        // SOCIAL ENGINEERING
        {
            id: 'verify_identity',
            pattern: /\b(verify your (identity|account)|confirm your (identity|account|details)|authenticate|re.?verify)\b/i,
            weight: 12,
            category: 'phishing',
            severity: 'medium',
            flag: 'Fake Account Verification Request',
            explanation: 'Fake verification requests trick you into entering your credentials on phishing sites. If your account truly needs verification, log in directly through the official app or website.'
        },
        {
            id: 'whatsapp_forward',
            pattern: /\b(forward (this|to)|share (this|with)|send (this|to) \d+ (people|friends|contacts|groups))\b/i,
            weight: 8,
            category: 'misinformation',
            severity: 'low',
            flag: 'Chain Message / Forward Request',
            explanation: 'Messages asking you to forward to others are often hoaxes or scams trying to spread. Legitimate important information comes through official channels, not chain forwards.'
        }
    ];

    // Category display info
    const categoryInfo = {
        urgency: { name: 'Urgency / Pressure Tactics', icon: 'fa-clock' },
        financial_fraud: { name: 'Financial Fraud', icon: 'fa-money-bill-wave' },
        credential_theft: { name: 'Credential Theft', icon: 'fa-key' },
        identity_theft: { name: 'Identity Theft', icon: 'fa-id-card' },
        phishing: { name: 'Phishing Attack', icon: 'fa-fish' },
        prize_scam: { name: 'Prize / Lottery Scam', icon: 'fa-gift' },
        job_scam: { name: 'Job / Employment Scam', icon: 'fa-briefcase' },
        investment_scam: { name: 'Investment Fraud', icon: 'fa-chart-line' },
        impersonation: { name: 'Impersonation / Spoofing', icon: 'fa-user-secret' },
        malware: { name: 'Malware / Device Compromise', icon: 'fa-virus' },
        threat_intimidation: { name: 'Threat & Intimidation', icon: 'fa-exclamation-triangle' },
        presentation: { name: 'Suspicious Presentation', icon: 'fa-exclamation-circle' },
        misinformation: { name: 'Misinformation / Chain Message', icon: 'fa-share-alt' }
    };

    /**
     * Analyze text for scam indicators
     * @param {string} text - The text to analyze
     * @param {string} incidentType - Selected incident type
     * @returns {Object} Analysis result
     */
    function analyze(text, incidentType = 'other') {
        if (!text || text.trim().length < 5) {
            return {
                score: 0,
                level: 'insufficient',
                category: null,
                flags: [],
                actions: [],
                message: 'Please provide more text to analyze.'
            };
        }

        const matchedRules = [];
        let totalScore = 0;
        const categoryCounts = {};
        const flagsFound = [];

        // Run each rule against the text
        rules.forEach(rule => {
            if (rule.pattern.test(text)) {
                matchedRules.push(rule);
                totalScore += rule.weight;
                categoryCounts[rule.category] = (categoryCounts[rule.category] || 0) + rule.weight;

                flagsFound.push({
                    id: rule.id,
                    flag: rule.flag,
                    severity: rule.severity,
                    explanation: rule.explanation,
                    category: rule.category,
                    categoryName: categoryInfo[rule.category]?.name || rule.category
                });
            }
        });

        // Context bonus based on incident type
        const contextBonus = getContextBonus(incidentType, matchedRules);
        totalScore += contextBonus;

        // Normalize score to 0-100
        const normalizedScore = Math.min(100, Math.round((totalScore / 80) * 100));

        // Determine risk level
        let level;
        if (normalizedScore >= 60) level = 'high';
        else if (normalizedScore >= 30) level = 'medium';
        else level = 'low';

        // Determine primary category
        const primaryCategory = Object.entries(categoryCounts)
            .sort((a, b) => b[1] - a[1])[0];

        const categoryKey = primaryCategory ? primaryCategory[0] : null;
        const categoryName = categoryKey ? categoryInfo[categoryKey]?.name : 'Unknown';

        // Sort flags by severity
        const severityOrder = { high: 0, medium: 1, low: 2 };
        flagsFound.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        // Generate actions
        const actions = generateActions(matchedRules, level, incidentType);

        return {
            score: normalizedScore,
            level,
            category: categoryName,
            categoryKey,
            categoryIcon: categoryKey ? categoryInfo[categoryKey]?.icon : 'fa-question',
            flags: flagsFound,
            actions,
            matchedRuleCount: matchedRules.length,
            allCategories: Object.keys(categoryCounts).map(k => ({
                key: k,
                name: categoryInfo[k]?.name || k,
                score: categoryCounts[k]
            }))
        };
    }

    function getContextBonus(incidentType, matchedRules) {
        let bonus = 0;
        const ruleIds = matchedRules.map(r => r.id);

        // If user selected UPI and payment-related rules matched
        if (incidentType === 'upi' && ruleIds.some(id => id.includes('upi') || id.includes('payment'))) {
            bonus += 8;
        }
        // Job scam context
        if (incidentType === 'job' && ruleIds.some(id => id.includes('job'))) {
            bonus += 8;
        }
        // Investment context
        if (incidentType === 'investment' && ruleIds.some(id => id.includes('invest') || id.includes('guaranteed'))) {
            bonus += 8;
        }

        return bonus;
    }

    function generateActions(matchedRules, level, incidentType) {
        const actions = [];
        const categories = [...new Set(matchedRules.map(r => r.category))];

        // Universal actions
        actions.push({
            icon: 'fa-ban',
            isDont: true,
            title: 'Do NOT click any links',
            description: 'Never click links in suspicious messages. Type the official website address directly in your browser.'
        });

        actions.push({
            icon: 'fa-key',
            isDont: true,
            title: 'Do NOT share credentials',
            description: 'Never share OTP, PIN, password, CVV, or bank details with anyone, regardless of who they claim to be.'
        });

        if (categories.includes('financial_fraud') || categories.includes('credential_theft')) {
            actions.push({
                icon: 'fa-phone-alt',
                isDont: false,
                title: 'Call your bank independently',
                description: 'Use the number on your card or bank\'s official website. Do NOT call numbers provided in the suspicious message.'
            });
        }

        if (categories.includes('malware')) {
            actions.push({
                icon: 'fa-mobile-alt',
                isDont: true,
                title: 'Do NOT install unknown apps',
                description: 'Never install apps (.apk files) from links. Only use official app stores (Google Play Store, Apple App Store).'
            });
        }

        if (categories.includes('impersonation') || categories.includes('threat_intimidation')) {
            actions.push({
                icon: 'fa-user-check',
                isDont: false,
                title: 'Verify the caller\'s identity independently',
                description: 'Never trust a caller\'s claimed identity. Hang up and contact the organization directly through their official number.'
            });
        }

        actions.push({
            icon: 'fa-camera',
            isDont: false,
            title: 'Preserve evidence',
            description: 'Take screenshots of messages, call logs, transaction details. This helps when reporting to authorities.'
        });

        actions.push({
            icon: 'fa-search',
            isDont: false,
            title: 'Verify independently',
            description: 'Search for the organization\'s official website or phone number and contact them directly to confirm the message.'
        });

        if (level === 'high') {
            actions.push({
                icon: 'fa-flag',
                isDont: false,
                title: 'Report to authorities',
                description: 'Report to the Cyber Crime Portal (cybercrime.gov.in) or call 1930. File an FIR for significant fraud.'
            });
        }

        return actions;
    }

    // Sample messages for demonstration
    const sampleMessages = {
        prize: `🎉 CONGRATULATIONS!!! 🎉
Dear Customer, you have been selected as the LUCKY WINNER of ₹50,00,000 in the Amazon Annual Lucky Draw!!! 
Click here to claim your prize NOW: http://amaz0n-prize.xyz/claim
Send your OTP and bank details to verify. Offer expires in 24 HOURS!!!
Processing fee of ₹999 must be paid via Google Pay. Hurry!!!`,

        bank: `URGENT: Dear Customer, your SBI account has been BLOCKED due to incomplete KYC verification. 
Your account will be permanently closed within 2 hours if not updated.
Click immediately to update KYC: http://sbi-kyc-update.tk/verify
Enter your account number, password, and ATM PIN to re-verify.
Call customer care: 9876543210 for immediate assistance.`,

        job: `Hi! Work from home opportunity 💰
Earn ₹5000-₹15000 per day by doing simple data entry!
No experience needed, no interview required!
Guaranteed income from Day 1!
Registration fee: ₹1500 only (refundable)
Send fee via PhonePe to 8765432109
Limited slots available - JOIN NOW!!!
Forward this to 10 friends to get bonus!`,

        kyc: `Dear Valued Customer,
Your PAN Card is linked to suspicious transactions. Your bank account will be frozen within 24 hours.
To avoid legal action and account freeze, update your KYC immediately.
Click: http://kyc-update-portal.online/verify
Required: Aadhaar number, PAN number, bank account details, mobile OTP.
This is from RBI Compliance Department.
Ignore at your own risk - case will be filed.`,

        investment: `📈 GUARANTEED RETURNS! Make ₹1,00,000 daily!
Join our exclusive Forex trading group on Telegram.
Our AI-powered system guarantees 500% returns in 30 days!
Risk-free investment - we guarantee no loss!
Minimum investment: ₹10,000 via Bitcoin only.
Previous members earned ₹50 lakhs in just 2 months!
JOIN NOW before slots fill up: t.me/crypto_profit_guru
Act fast - limited time offer!!!`,

        legitimate: `Your order #AMZ-78234 has been shipped via BlueDart. 
Expected delivery: 15 Jan 2025. 
Track your order on the Amazon app or visit amazon.in. 
For help, call 1800-3000-9009 (toll-free). 
Thank you for shopping with us.`
    };

    return {
        analyze,
        sampleMessages,
        categoryInfo,
        rules
    };
})();
