"""
MdhalaScan v1.0 - Email Scanner Module
Email Phishing Scanner with URL Analysis
"""

import re
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse
from datetime import datetime

# Import from utils
from utils import Fore, COLORS_ENABLED, ProgressBar
# Import URL scanner
from urlscan import URLScanner
# Import other modules
from intelligence import PhishingIntelligenceDB
from ipscan import IPIntelligenceDB

class EmailScanner:
    """Email Phishing Scanner Module with URL Analysis"""
    
    def __init__(self, phishing_intel: Optional[PhishingIntelligenceDB] = None,
                 ip_intel: Optional[IPIntelligenceDB] = None):
        self.findings = []
        self.risk_score = 0
        self.detected_urls = []
        self.url_scanner = URLScanner(phishing_intel, ip_intel)  # Pass both intels
        self.progress_bar = ProgressBar()
        self.urgency_keywords = [
            'urgent', 'immediate', 'required', 'suspended',
            'locked', 'verify now', 'click here', 'account',
            'password', 'security', 'update', 'confirm',
            'action required', 'attention needed', 'important',
            'security alert', 'unauthorized access', 'compromised',
            'verify your identity', 'password expired', 'account suspended'
        ]
        self.suspicious_domains = [
            'gmail-security.com', 'apple-verify.net',
            'microsoft-update.org', 'paypal-confirm.com',
            'google-security.net', 'facebook-verify.org',
            'amazon-update.com', 'netflix-confirm.net',
            'bank-verify.com', 'paypal-secure.net'
        ]
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content"""
        return self.url_scanner.extract_urls_from_text(text)
    
    def analyze_headers(self, headers: str) -> int:
        """Analyze email headers for inconsistencies"""
        score = 0
        
        # Check for From vs Reply-To mismatch
        from_match = re.search(r'From:\s*.*?<.*?@([^>]*)>', headers, re.IGNORECASE)
        reply_match = re.search(r'Reply-To:\s*.*?<.*?@([^>]*)>', headers, re.IGNORECASE)
        
        if from_match and reply_match:
            from_domain = from_match.group(1).lower().strip()
            reply_domain = reply_match.group(1).lower().strip()
            if from_domain != reply_domain:
                self.findings.append(f"❌ From ({from_domain}) and Reply-To ({reply_domain}) domains don't match")
                score += 20
        
        # Check for suspicious sending domains
        for domain in self.suspicious_domains:
            if domain in headers.lower():
                self.findings.append(f"⚠️  Suspicious sending domain: {domain}")
                score += 15
        
        # Check for missing/weak security headers
        headers_lower = headers.lower()
        
        # SPF check
        if 'spf=pass' in headers_lower:
            self.findings.append("✓ SPF check passed")
        elif 'spf=fail' in headers_lower or 'spf=softfail' in headers_lower:
            self.findings.append("❌ SPF check failed")
            score += 15
        else:
            self.findings.append("⚠️  SPF check information not found")
            score += 5
        
        # DKIM check
        if 'dkim=pass' in headers_lower:
            self.findings.append("✓ DKIM signature verified")
        elif 'dkim=fail' in headers_lower:
            self.findings.append("❌ DKIM signature failed")
            score += 15
        else:
            self.findings.append("⚠️  DKIM signature not found")
            score += 5
        
        # DMARC check
        if 'dmarc=pass' in headers_lower:
            self.findings.append("✓ DMARC check passed")
        elif 'dmarc=fail' in headers_lower:
            self.findings.append("❌ DMARC check failed")
            score += 10
        
        # Check for impersonation in display name
        display_name_patterns = [
            (r'From:.*?(Microsoft|Windows|Apple|Google|Amazon|PayPal|Facebook|Netflix|Bank)', 
             "⚠️  Brand name in display name (possible impersonation)", 10),
            (r'From:.*?(Support|Security|Admin|Administrator|IT Department|Help Desk)',
             "⚠️  Generic authority name in display name", 5),
        ]
        
        for pattern, message, penalty in display_name_patterns:
            if re.search(pattern, headers, re.IGNORECASE):
                self.findings.append(message)
                score += penalty
        
        return score
    
    def analyze_content(self, body: str) -> int:
        """Analyze email body content"""
        score = 0
        body_lower = body.lower()
        
        # Check for urgency keywords
        urgency_count = 0
        detected_keywords = []
        for keyword in self.urgency_keywords:
            if keyword in body_lower:
                count = body_lower.count(keyword)
                urgency_count += count
                detected_keywords.append(keyword)
        
        if urgency_count > 3:
            keywords_str = ', '.join(set(detected_keywords[:5]))
            if len(set(detected_keywords)) > 5:
                keywords_str += ', ...'
            self.findings.append(f"⚠️  {urgency_count} urgency keywords detected: {keywords_str}")
            score += min(urgency_count * 2, 25)
        
        # Extract and check URLs
        urls = self.extract_urls_from_text(body)
        self.detected_urls = urls
        
        if urls:
            self.findings.append(f"⚠️  {len(urls)} URLs found in email")
            score += min(len(urls) * 3, 15)
            
            # Check URLs for suspicious patterns
            suspicious_urls = []
            for url in urls[:10]:
                url_lower = url.lower()
                if any(sd in url_lower for sd in self.suspicious_domains):
                    suspicious_urls.append(url)
                    score += 10
                
                ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                if re.search(ip_pattern, url):
                    suspicious_urls.append(url)
                    score += 15
            
            if suspicious_urls:
                for url in suspicious_urls[:3]:
                    display_url = url[:60] + '...' if len(url) > 60 else url
                    self.findings.append(f"❌ Suspicious URL detected: {display_url}")
        
        # Check for attachment mentions
        attachment_keywords = ['attachment', 'attached', 'download', 'file', 'document', 
                              'invoice', 'receipt', 'statement', 'bill', 'form']
        attachment_count = sum(1 for kw in attachment_keywords if kw in body_lower)
        
        if attachment_count > 2:
            self.findings.append(f"⚠️  Multiple attachment mentions ({attachment_count})")
            score += 10
        
        # Check for impersonation attempts
        impersonation_indicators = [
            ('dear customer', 5, "Generic greeting"),
            ('valued member', 5, "Generic greeting"),
            ('account holder', 5, "Generic greeting"),
            ('security team', 10, "Authority impersonation"),
            ('support department', 10, "Authority impersonation"),
            ('administrator', 10, "Authority impersonation"),
            ('it department', 10, "Authority impersonation"),
            ('hr department', 10, "Authority impersonation"),
        ]
        
        for indicator, penalty, description in impersonation_indicators:
            if indicator in body_lower:
                self.findings.append(f"⚠️  {description} detected")
                score += penalty
        
        # Check for grammatical errors
        informal_patterns = [
            (r'\b(?:ur|u r|u)\b', 5, "Informal language (ur/u)"),
            (r'\bplz\b|\bpls\b', 5, "Informal language (plz/pls)"),
            (r'\bthx\b|\btnx\b', 5, "Informal language (thx/tnx)"),
            (r'!!!+', 3, "Excessive exclamation marks"),
        ]
        
        for pattern, penalty, description in informal_patterns:
            if re.search(pattern, body_lower):
                self.findings.append(f"⚠️  {description}")
                score += penalty
        
        # Check for threats or consequences
        threat_keywords = [
            'close your account', 'suspend your account', 'terminate your account',
            'legal action', 'fines', 'penalties', 'immediately', 'within 24 hours',
            'last chance', 'final warning', 'account will be deleted'
        ]
        
        for keyword in threat_keywords:
            if keyword in body_lower:
                self.findings.append(f"❌ Threat detected: '{keyword}'")
                score += 15
        
        return score
    
    def scan_embedded_urls(self, urls: List[str], max_urls: int = 5) -> Dict:
        """Scan URLs found in the email"""
        url_results = {
            'total_urls': len(urls),
            'scanned_urls': min(len(urls), max_urls),
            'high_risk_urls': 0,
            'suspicious_urls': 0,
            'safe_urls': 0,
            'detailed_results': []
        }
        
        if not urls:
            return url_results
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔗 Scanning {min(len(urls), max_urls)} embedded URLs...")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 60}")
        
        urls_to_scan = urls[:max_urls]
        
        for i, url in enumerate(urls_to_scan, 1):
            print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}URL {i}/{len(urls_to_scan)}: {url[:50]}...")
            
            # Scan the URL
            url_result = self.url_scanner.scan_single_url(url, show_progress=False)
            
            # Categorize by risk
            if url_result['risk_score'] > 60:
                url_results['high_risk_urls'] += 1
                risk_category = "HIGH RISK"
                color = Fore.RED if COLORS_ENABLED else ''
            elif url_result['risk_score'] > 30:
                url_results['suspicious_urls'] += 1
                risk_category = "SUSPICIOUS"
                color = Fore.YELLOW if COLORS_ENABLED else ''
            else:
                url_results['safe_urls'] += 1
                risk_category = "SAFE"
                color = Fore.GREEN if COLORS_ENABLED else ''
            
            # Add to detailed results
            url_summary = {
                'url': url,
                'risk_score': url_result['risk_score'],
                'risk_category': risk_category,
                'key_findings': url_result['findings'][:3] if url_result['findings'] else ["No major issues detected"]
            }
            url_results['detailed_results'].append(url_summary)
            
            # Print quick result with progress bar
            print(f"{self.progress_bar.create_risk_bar(url_result['risk_score'], 30)}")
            
            # Add URL findings to email findings if high risk
            if url_result['risk_score'] > 60:
                self.findings.append(f"❌ HIGH RISK URL: {url[:50]}... (Score: {url_result['risk_score']}/100)")
                if url_result['findings']:
                    self.findings.append(f"    → {url_result['findings'][0]}")
            elif url_result['risk_score'] > 30:
                self.findings.append(f"⚠️  Suspicious URL: {url[:50]}... (Score: {url_result['risk_score']}/100)")
        
        return url_results
    
    def scan_email(self, headers: str, body: str, scan_urls: bool = True) -> Dict:
        """Main email scanning function"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📧 Scanning Email Content")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        # Reset findings
        self.findings = []
        self.risk_score = 0
        self.detected_urls = []
        
        # Show animated scanning
        self.progress_bar.show_animated_scanning("Analyzing email content...")
        
        # Perform email analysis
        print(f"{self.progress_bar.create_scan_progress(1, 2, 'Analyzing headers and content...')}")
        self.risk_score += self.analyze_headers(headers)
        self.risk_score += self.analyze_content(body)
        
        # Scan embedded URLs if requested and URLs found
        url_scan_results = None
        if scan_urls and self.detected_urls:
            print(f"{self.progress_bar.create_scan_progress(2, 2, 'Scanning embedded URLs...')}")
            url_scan_results = self.scan_embedded_urls(self.detected_urls)
            
            # Adjust email risk score based on URL scan results
            if url_scan_results['high_risk_urls'] > 0:
                self.risk_score += min(url_scan_results['high_risk_urls'] * 10, 30)
            if url_scan_results['suspicious_urls'] > 0:
                self.risk_score += min(url_scan_results['suspicious_urls'] * 5, 20)
        
        # Cap score at 100
        self.risk_score = min(self.risk_score, 100)
        
        return {
            'risk_score': self.risk_score,
            'findings': self.findings,
            'detected_urls': self.detected_urls,
            'url_scan_results': url_scan_results,
            'timestamp': datetime.now().isoformat(),
            'timestamp': datetime.now().isoformat(), #added for the timestamp
            'scanner_version': '1.8'
        }