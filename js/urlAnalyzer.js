/**
 * CYBER SHIELD — URL Heuristic Analyzer
 * Checks basic indicators without visiting or opening the URL.
 */

const URLAnalyzer = (() => {
    const suspiciousTLDs = [
        '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.buzz',
        '.club', '.icu', '.work', '.site', '.online', '.live', '.store',
        '.fun', '.space', '.website', '.tech', '.link', '.win', '.bid'
    ];

    const trustedDomains = [
        'google.com', 'facebook.com', 'amazon.in', 'amazon.com',
        'flipkart.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
        'rbi.org.in', 'gov.in', 'nic.in', 'microsoft.com',
        'apple.com', 'whatsapp.com', 'instagram.com', 'twitter.com',
        'youtube.com', 'paytm.com', 'phonepe.com', 'npci.org.in'
    ];

    const shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
        'is.gd', 'buff.ly', 'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at'
    ];

    const lookalikes = [
        { fake: /g00gle|go0gle|googie|gooogle/i, real: 'google.com' },
        { fake: /amaz0n|amazom|arnazon|amazon-[a-z]/i, real: 'amazon.com/in' },
        { fake: /faceb00k|facebo0k|faecbook/i, real: 'facebook.com' },
        { fake: /paypa[l1i]|paypai|paypa-/i, real: 'paypal.com' },
        { fake: /micr0soft|mircosoft|micosoft/i, real: 'microsoft.com' },
        { fake: /app[l1]e|appie/i, real: 'apple.com' },
        { fake: /netf[l1]ix|netfiix/i, real: 'netflix.com' },
        { fake: /flipk[a@]rt|fl[i1]pkart/i, real: 'flipkart.com' },
        { fake: /whatsap[^p]|whatssapp|wh[a@]tsapp/i, real: 'whatsapp.com' },
        { fake: /sbi[^.]/i, real: 'sbi.co.in' },
        { fake: /hdfc[^b]/i, real: 'hdfcbank.com' }
    ];

    function analyze(url) {
        if (!url || url.trim().length === 0) {
            return { score: 0, flags: [], level: 'insufficient' };
        }

        const flags = [];
        let score = 0;

        // Clean URL
        url = url.trim().toLowerCase();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }

        let parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch {
            flags.push({
                flag: 'Invalid URL Format',
                severity: 'medium',
                explanation: 'The URL is malformed, which could indicate a crafted malicious link.'
            });
            return { score: 40, flags, level: 'medium' };
        }

        const hostname = parsedUrl.hostname;
        const fullUrl = parsedUrl.href;

        // Check HTTP vs HTTPS
        if (parsedUrl.protocol === 'http:') {
            score += 10;
            flags.push({
                flag: 'No HTTPS (Unencrypted)',
                severity: 'medium',
                explanation: 'This URL uses HTTP instead of HTTPS, meaning data sent to this site is not encrypted. Most legitimate sites use HTTPS.'
            });
        }

        // Check suspicious TLDs
        suspiciousTLDs.forEach(tld => {
            if (hostname.endsWith(tld)) {
                score += 15;
                flags.push({
                    flag: `Suspicious Domain Extension (${tld})`,
                    severity: 'medium',
                    explanation: `The domain extension "${tld}" is frequently used by scammers because it is cheap and easy to register anonymously.`
                });
            }
        });

        // Check URL shorteners
        shorteners.forEach(shortener => {
            if (hostname === shortener || hostname.endsWith('.' + shortener)) {
                score += 15;
                flags.push({
                    flag: 'URL Shortener Detected',
                    severity: 'medium',
                    explanation: `This is a shortened URL (${shortener}) that hides the real destination. Scammers use shorteners to disguise malicious websites.`
                });
            }
        });

        // Check lookalike domains
        lookalikes.forEach(entry => {
            if (entry.fake.test(hostname)) {
                score += 25;
                flags.push({
                    flag: `Possible Typosquatting (Impersonating ${entry.real})`,
                    severity: 'high',
                    explanation: `This domain appears to mimic "${entry.real}" using similar-looking characters. This technique is called typosquatting and is a common phishing tactic.`
                });
            }
        });

        // Check for IP address in URL
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
            score += 20;
            flags.push({
                flag: 'IP Address Instead of Domain Name',
                severity: 'high',
                explanation: 'Using an IP address instead of a domain name is suspicious. Legitimate organizations use proper domain names, not raw IP addresses.'
            });
        }

        // Check for suspicious subdomains
        const parts = hostname.split('.');
        if (parts.length > 3) {
            score += 10;
            flags.push({
                flag: 'Excessive Subdomains',
                severity: 'medium',
                explanation: 'Multiple subdomains (e.g., secure.login.bank.scamsite.com) are used to make phishing URLs look like they belong to a trusted organization.'
            });
        }

        // Check for sensitive words in path
        const sensitivePathWords = /\/(login|verify|secure|account|banking|update|confirm|password|otp|kyc|auth)/i;
        if (sensitivePathWords.test(parsedUrl.pathname)) {
            score += 12;
            flags.push({
                flag: 'Sensitive Action Words in URL Path',
                severity: 'medium',
                explanation: 'The URL path contains words like "login", "verify", or "password" which suggest it might be a phishing page designed to steal credentials.'
            });
        }

        // Check for @ symbol in URL (can trick some browsers)
        if (fullUrl.includes('@')) {
            score += 18;
            flags.push({
                flag: '@ Symbol in URL',
                severity: 'high',
                explanation: 'An @ symbol in a URL can trick browsers into ignoring the actual domain. This is a well-known phishing technique.'
            });
        }

        // Check against trusted domains
        const isTrusted = trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d));
        if (isTrusted && flags.length === 0) {
            return {
                score: 5,
                flags: [{
                    flag: 'Domain Appears Legitimate',
                    severity: 'low',
                    explanation: 'This domain matches a known trusted domain. However, always verify the complete URL carefully — including the path and parameters.'
                }],
                level: 'low',
                note: 'A domain match does NOT guarantee safety. Always check the complete URL.'
            };
        }

        // Normalize score
        const normalizedScore = Math.min(100, Math.round((score / 60) * 100));
        let level;
        if (normalizedScore >= 60) level = 'high';
        else if (normalizedScore >= 30) level = 'medium';
        else level = 'low';

        return { score: normalizedScore, flags, level };
    }

    return { analyze };
})();
