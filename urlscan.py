"""
MdhalaScan - URL Scanner Module
Enhanced URL Phishing Scanner with Phishing Intelligence & IP Reputation
"""

import re
import socket
import ssl
import time
import hashlib
import warnings
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse

warnings.filterwarnings('ignore')

# Import from utils
from utils import (
    Fore, COLORS_ENABLED, Style, 
    TrustedDomains, AbusedInfrastructureDB, ProgressBar,
    SUSPICIOUS_KEYWORDS, HIGH_RISK_TLDS, URL_SHORTENERS, 
    BRAND_NAMES, SUSPICIOUS_PATTERNS
)
# Import other modules
from intelligence import PhishingIntelligenceDB
from ipscan import IPIntelligenceDB

class URLScanner:
    """Enhanced URL Phishing Scanner with Phishing Intelligence & IP Reputation"""
    
    def __init__(self, phishing_intel: Optional[PhishingIntelligenceDB] = None, 
                 ip_intel: Optional[IPIntelligenceDB] = None):
        self.findings = []
        self.risk_score = 0
        self.detected_urls = []
        self.progress_bar = ProgressBar()
        self.trusted_domains = TrustedDomains()
        self.abused_infra = AbusedInfrastructureDB()
        self.phishing_intel = phishing_intel
        self.ip_intel = ip_intel  # New: IP intelligence integration
        
        # Suspicious patterns (already imported from utils)
        self.brand_names = BRAND_NAMES
        self.url_shorteners = URL_SHORTENERS
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS
        self.high_risk_tlds = HIGH_RISK_TLDS
        self.suspicious_patterns = SUSPICIOUS_PATTERNS
    
    def reset_scanner(self):
        """Reset scanner state for new scan"""
        self.findings = []
        self.risk_score = 0
        self.detected_urls = []
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content"""
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        cleaned_urls = []
        for url in urls:
            url = url.rstrip('.,;:!?)')
            cleaned_urls.append(url)
        return cleaned_urls
    
    def get_url_details(self, url: str) -> Dict:
        """Get detailed URL information"""
        details = {
            'domain': 'N/A',
            'main_domain': 'N/A',
            'tld': 'N/A',
            'subdomain_count': 0,
            'https': False,
            'ip_address': 'N/A',
            'full_url': url
        }
        
        try:
            parsed = urlparse(url)
            
            # Domain extraction
            extracted = tldextract.extract(url)
            details['domain'] = f"{extracted.domain}.{extracted.suffix}"
            details['main_domain'] = extracted.domain
            details['tld'] = f".{extracted.suffix}" if extracted.suffix else 'N/A'
            
            # Subdomain count
            if extracted.subdomain:
                subdomains = [s for s in extracted.subdomain.split('.') if s]
                details['subdomain_count'] = len(subdomains)
            
            # HTTPS check
            details['https'] = parsed.scheme.lower() == 'https'
            
            # IP address resolution
            try:
                # Try to resolve the domain
                hostname = parsed.netloc
                if hostname:
                    # Remove port if present
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    
                    # Check if it's already an IP
                    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    if re.match(ip_pattern, hostname):
                        details['ip_address'] = hostname
                    else:
                        # DNS resolution
                        ip = socket.gethostbyname(hostname)
                        details['ip_address'] = ip
            except (socket.gaierror, socket.error):
                details['ip_address'] = 'DNS resolution failed'
            except Exception:
                details['ip_address'] = 'Resolution error'
                
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def check_domain_exists(self, domain: str) -> bool:
        """Check if a domain exists via DNS resolution"""
        try:
            extracted = tldextract.extract(domain)
            socket.gethostbyname(extracted.domain)
            return True
        except socket.gaierror:
            return False
        except:
            return False
    
    def get_domain_hash_score(self, domain: str) -> int:
        """Get consistent hash-based score for domain (deterministic)"""
        # Skip hash scoring for trusted domains
        is_trusted, _ = self.trusted_domains.is_trusted_domain(domain)
        if is_trusted:
            return 0
        
        # Create a hash of the domain and use it to generate a consistent score
        domain_hash = hashlib.md5(domain.encode()).hexdigest()
        hash_int = int(domain_hash[:4], 16)
        
        # Map hash to 0-20 range deterministically
        score = hash_int % 21  # 0-20
        
        # Check for high-risk TLDs
        for tld in self.high_risk_tlds:
            if domain.endswith(tld):
                score += 15
                break
        
        # Check for suspicious patterns
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain
        
        for pattern, penalty, description in self.suspicious_patterns:
            if re.match(pattern, domain_name):
                score += penalty
                break
        
        return min(score, 30)
    
    def analyze_url_structure(self, url: str) -> int:
        """Analyze URL structure for suspicious patterns"""
        score = 0
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check URL length
        if len(url) > 100:
            self.findings.append("❌ URL is unusually long (>100 characters)")
            score += 15
        
        # Check for IP address
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, url):
            self.findings.append("❌ URL uses IP address instead of domain name")
            score += 20
        
        # Check for excessive special characters
        special_chars = len(re.findall(r'[%&#@!\$\*\+]', url))
        if special_chars > 5:
            self.findings.append(f"⚠️  URL contains {special_chars} special characters")
            score += min(special_chars * 2, 20)
        
        # Check for URL shorteners
        for shortener in self.url_shorteners:
            if shortener in domain:
                self.findings.append(f"⚠️  Uses URL shortener ({shortener})")
                score += 15
                break
        
        # Check for @ symbol (credentials in URL)
        if '@' in url:
            self.findings.append("❌ URL contains '@' symbol (possible credential injection)")
            score += 25
        
        # Check for multiple subdomains
        subdomains = domain.count('.')
        if subdomains > 3:
            self.findings.append(f"⚠️  Multiple subdomains ({subdomains} levels)")
            score += min(subdomains * 3, 15)
        
        # Check for hex encoded strings
        hex_pattern = r'%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}'
        if re.search(hex_pattern, url):
            self.findings.append("⚠️  Hex-encoded strings detected")
            score += 15
        
        return score
    
    def analyze_domain(self, url: str) -> int:
        """Analyze domain characteristics with improved detection"""
        score = 0
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            base_domain = extracted.domain.lower()
            
            # Check if domain exists FIRST
            domain_exists = self.check_domain_exists(domain)
            if not domain_exists:
                self.findings.append("❌ Domain does not exist (DNS resolution failed)")
                score += 30  # High risk for non-existent domains
                
                # Check for typosquatting even if domain doesn't exist
                for brand in self.brand_names:
                    if self.is_typosquatting(domain.lower(), brand):
                        self.findings.append(f"❌ Non-existent domain resembles '{brand}' (HIGH RISK)")
                        score += 40  # Even higher risk!
                        break
                
                # Return early with high score for non-existent domains
                return min(score, 70)
            
            # Domain exists, continue with normal analysis
            # Check if domain is trusted
            is_trusted, trust_info = self.trusted_domains.is_trusted_domain(domain)
            if is_trusted:
                self.findings.append(f"✓ Trusted {trust_info['category']} domain")
                # Trusted domains get reduced scoring
                return max(score - 10, 0)
            
            # Check for typosquatting for non-trusted domains
            for brand in self.brand_names:
                if brand in domain.lower() and domain.lower() != brand + '.' + extracted.suffix:
                    if self.is_typosquatting(domain.lower(), brand):
                        self.findings.append(f"❌ Possible typosquatting: resembles '{brand}'")
                        score += 35  # Higher penalty for typosquatting
                        break
            
            # Check domain age using deterministic scoring
            domain_age_risk = self.get_domain_hash_score(domain)
            if domain_age_risk > 15:
                self.findings.append(f"⚠️  Domain shows characteristics of recent or suspicious registration")
                score += domain_age_risk
            
            # Check SSL/TLS
            ssl_result = self.check_ssl_certificate(extracted.domain, domain)
            if ssl_result['valid']:
                self.findings.append("✓ SSL/TLS certificate present and valid")
                if ssl_result.get('expiring_soon'):
                    self.findings.append(f"⚠️  SSL certificate expires in {ssl_result['days_to_expiry']} days")
                    score += 5
            else:
                if ssl_result['error'] == "NO_SSL":
                    self.findings.append("❌ No SSL/TLS certificate detected (HTTP only)")
                    score += 25
                elif ssl_result['error']:
                    self.findings.append(f"⚠️  SSL check incomplete: {ssl_result['error']}")
                    score += 10
            
            # Check for suspicious TLDs
            for tld in self.high_risk_tlds:
                if domain.endswith(tld):
                    self.findings.append(f"⚠️  Uses high-risk TLD: {tld}")
                    score += 20
                    break
            
            # Check for suspicious keywords in domain
            suspicious_domain_keywords = ['login', 'verify', 'secure', 'account', 'bank', 
                                         'pay', 'wallet', 'update', 'confirm', 'password']
            for keyword in suspicious_domain_keywords:
                if keyword in domain.lower():
                    self.findings.append(f"⚠️  Suspicious keyword '{keyword}' in domain")
                    score += 10
                    break
            
        except Exception as e:
            self.findings.append(f"⚠️  Domain analysis incomplete: {str(e)[:50]}...")
        
        return min(score, 70)
    
    def check_ssl_certificate(self, domain_name: str, full_domain: str) -> Dict:
        """Check SSL certificate with better handling"""
        result = {
            'valid': False,
            'error': None,
            'expiring_soon': False,
            'days_to_expiry': 0
        }
        
        # Skip SSL check for very short domain names
        if len(domain_name) < 3:
            return result
        
        # Check if domain is trusted
        is_trusted, _ = self.trusted_domains.is_trusted_domain(full_domain)
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try multiple domain variations
            domains_to_try = [domain_name, f"www.{domain_name}"]
            
            for test_domain in domains_to_try:
                try:
                    with socket.create_connection((test_domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=test_domain) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                result['valid'] = True
                                not_after = cert.get('notAfter', '')
                                if not_after:
                                    try:
                                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                        days_to_expiry = (expiry_date - datetime.now()).days
                                        result['days_to_expiry'] = days_to_expiry
                                        if days_to_expiry < 30:
                                            result['expiring_soon'] = True
                                    except:
                                        pass
                                break
                except (ConnectionRefusedError, TimeoutError):
                    continue
                except ssl.SSLError:
                    continue
            
            if not result['valid']:
                # Try HTTP instead of HTTPS
                try:
                    response = requests.get(f"http://{domain_name}", timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        result['error'] = "NO_SSL"
                except:
                    result['error'] = "Connection failed"
                    
        except socket.gaierror:
            result['error'] = "DNS resolution failed"
        except Exception as e:
            result['error'] = f"Error: {str(e)[:30]}"
        
        return result
    
    def is_typosquatting(self, domain: str, brand: str) -> bool:
        """Improved typosquatting detection"""
        # Common typos patterns for major brands
        common_typos = {
            # Banking
            'chase': ['ch@se', 'ch4se', 'chas3', 'chase-login', 'chase-bank', 'chas3-bank', 'ch4se-login'],
            'wellsfargo': ['wellsfarg0', 'wellsfarg0-login', 'wells-fargo', 'wellsfargo-login', 'wellsfargo-banking'],
            'citibank': ['citib@nk', 'citibank-login', 'citi-bank', 'cit1bank', 'c1tibank'],
            'hsbc': ['h5bc', 'hsbclogin', 'hsbc-login', 'hsbc-online', 'h5bc-login'],
            'barclays': ['barcl@ys', 'barclays-login', 'barclays-online', 'b@rclays', 'barcla1s'],
            'bankofamerica': ['bankofamer1ca', 'bankofamerica-login', 'bofa', 'bank0famerica', 'b0fa-login'],
            'capitalone': ['capital0ne', 'capitalone-login', 'capital-one', 'cap1talone'],
            'americanexpress': ['americanexpress-login', 'amex', 'amex-login', '@mericanexpress', '4mericanexpress'],
            # PayPal (enhanced)
            'paypal': ['paypall', 'paypa1', 'paypai', 'paypaI', 'paypa!', 'paypa|', 
                      'paypal-login', 'paypa1-login', 'paypal-secure', 'paypal-update',
                      'verify-paypal', 'paypal-confirm', 'paypal-billing'],
            # Email
            'outlook': ['outl00k', 'outlook-login', 'outlook-office', 'outl0ok', '0utlook'],
            'gmail': ['gmai1', 'gma1l', 'gmail-login', 'gmail-account', 'gma1l-login', 'gm@il'],
            'yahoo': ['yah00', 'yahoo-mail', 'yahoo-login', 'y@hoo', 'yah00-login'],
            'protonmail': ['protonmail-login', 'proton-mail', 'pr0tonmail', 'protonma1l'],
            'aol': ['ao1', 'aol-mail', 'aol-login', '@ol', '4ol'],
            # E-commerce
            'ebay': ['eb@y', '3bay', 'ebay-login', 'ebay-account', 'eb@y-login'],
            'etsy': ['etsy-shop', 'etsy-login', '3tsy', 'etsy-account'],
            'aliexpress': ['aliexpress-login', 'aliexpr3ss', 'aliexpress-account', '@liexpress'],
            'alibaba': ['alibaba-login', 'alibaba-account', '@libaba', '4libaba'],
            'shopify': ['shopify-login', 'shopify-admin', 'sh0pify', 'shop1fy'],
            'amazon': ['amaz0n', 'amazonn', '@mazon', '4mazon', 'amazon-login', 'amaz0n-login',
                      'amazon-account', 'amazon-verify', 'amazon-update', 'amazon-billing'],
            # Professional & Business
            'linkedin': ['linked1n', 'linkedin-login', 'linkedin-account', '1inkedin', 'l1nkedin'],
            'slack': ['sl@ck', 'slack-login', 'slack-workspace', 'sl4ck', 'sl@ck-login'],
            'zoom': ['z00m', 'zoom-login', 'zoom-meeting', 'z00m-login', 'z0om'],
            'microsoft': ['micros0ft', 'micr0soft', 'mircosoft', 'microsoftt', 'm1crosoft',
                         'microsoft-login', 'office365-login', 'microsoft-account',
                         'windows-login', 'microsoft-verify'],
            'salesforce': ['salesforce-login', 'salesforce-account', 's@lesforce', 'salesf0rce'],
            'github': ['github-login', 'github-account', 'g1thub', 'gith@b'],
            'gitlab': ['gitlab-login', 'gitlab-account', 'g1tlab', 'gitl@b'],
            # Streaming & Entertainment
            'netflix': ['netf1ix', 'netfl1x', 'netfiix', 'netfl!x', 'netf|ix',
                       'netflix-login', 'netflix-account', 'netflix-billing',
                       'netflix-update', 'netflix-verify'],
            'spotify': ['spot1fy', 'spotify-login', 'spotify-account', 'sp0tify', 'spot1fy-login'],
            'youtube': ['youtub3', 'youtube-login', 'youtube-account', 'y0utube', 'youtub3-login'],
            'twitch': ['tw1tch', 'twitch-login', 'twitch-account', 'tw1tch-login', 'tw@tch'],
            'hulu': ['hulu-login', 'hulu-account', 'hulu-billing', 'hululogin'],
            'disneyplus': ['disneyplus-login', 'disneyplus-account', 'disney-plus', 'd1sneyplus'],
            'hbo': ['hbo-max', 'hbo-login', 'hbomax-login', 'hb0', 'hbo-account'],
            'paramount': ['paramount-login', 'paramount-plus', 'paramount-account'],
            # Social Media
            'facebook': ['faceb00k', 'facebok', 'facebo0k', 'facebookk', 'f@cebook', 'face-book',
                        'fb-login', 'facebook-login', 'facebook-account', 'facebook-verify',
                        'facebook-secure', 'facebook-update', 'fb-account'],
            'instagram': ['instagr@m', 'instagrarn', 'instagram-login', 'instagram-account',
                         'insta-verify', 'instagr@m-login', 'inst4gram'],
            'twitter': ['tw1tter', 'twitter-login', 'twitter-account', 'twitter-verify',
                       'tw1tter-login', 'tw@tter', 'x-login', 'x-account'],
            'tiktok': ['tiktok-login', 'tiktok-account', 'tikt0k', 't1ktok', 'tiktok-verify'],
            'pinterest': ['pintrest', 'p1nterest', 'p!nterest', 'pinterrest', 'pint3rest',
                         'pinterest-login', 'pinterest-account', 'pinterest-verify'],
            'snapchat': ['snapchat-login', 'snapchat-account', 'sn@pchat', 'sn4pchat'],
            'reddit': ['reddit-login', 'reddit-account', 'redd1t', 'redd!t', 'r3ddit'],
            'discord': ['discord-login', 'discord-account', 'd1scord', 'd!scord', 'disc0rd'],
            'whatsapp': ['whatsapp-web', 'whatsapp-login', 'whatsapp-account', 'whats@pp', 'whats4pp'],
            'telegram': ['telegram-login', 'telegram-account', 'telegram-web', 'telegr@m', 'telegr4m'],
            # Cloud
            'dropbox': ['dropbox-login', 'dropbox-account', 'dropb0x', 'dr0pbox', 'dropb0x-login'],
            'onedrive': ['onedrive-login', 'onedrive-account', 'onedr1ve', '0nedrive'],
            'google': ['goog1e', 'g00gle', 'googel', 'g00g1e', 'googIe', 'goog!e',
                      'google-login', 'g00gle-login', 'google-account', 'google-verify',
                      'google-drive', 'google-photos', 'google-cloud'],
            'apple': ['app1e', 'appie', 'aple', 'appIe', 'app!e', '@pple', '4pple',
                     'apple-id', 'app1e-id', 'apple-login', 'apple-account', 'icloud-login',
                     'apple-verify', 'apple-billing'],
            'adobe': ['adobe-login', 'adobe-account', 'ad0be', '@dobe', 'adobe-creative-cloud'],
            # Security & VPN
            'nordvpn': ['nordvpn-login', 'nordvpn-account', 'n0rdvpn', 'nordvpnn'],
            'expressvpn': ['expressvpn-login', 'expressvpn-account', 'expressvpn-billing'],
            'lastpass': ['lastpass-login', 'lastpass-account', 'l@stpass', 'lastp@ss'],
            '1password': ['1password-login', '1password-account', 'onepassword', '1p@ssword'],
            'dashlane': ['dashlane-login', 'dashlane-account', 'd@shlane', 'dashl@ne'],
            # Gaming Platforms
            'steam': ['steam-login', 'steam-account', 'steam-community', 'st3am', 'ste@m'],
            'epicgames': ['epicgames-login', 'epicgames-account', 'epic-games', 'ep1cgames'],
            'xbox': ['xbox-login', 'xbox-account', 'xbox-live', 'xb0x', 'xb0x-login'],
            'playstation': ['playstation-login', 'playstation-account', 'playstation-network', 'pl@ystation'],
            'nintendo': ['nintendo-login', 'nintendo-account', 'nintendo-network', 'n1ntendo'],
            'origin': ['origin-login', 'origin-account', '0rigin', 'origin-ea'],
            'battlenet': ['battlenet-login', 'battlenet-account', 'battlenet-bnet', 'b@ttlenet'],
            # Ride-Sharing & Delivery
            'uber': ['uber-login', 'uber-account', 'uber-rides', 'ub3r', 'ub3r-login'],
            'lyft': ['lyft-login', 'lyft-account', 'lyft-rides', 'lyft-driver', '1yft'],
            'doordash': ['doordash-login', 'doordash-account', 'doordash-driver', 'do0rdash'],
            'ubereats': ['ubereats-login', 'ubereats-account', 'ubereats-delivery', 'ub3reats'],
            'grubhub': ['grubhub-login', 'grubhub-account', 'grubhub-delivery', 'grubh@b'],
            # Crypto & Trading Platforms
            'coinbase': ['coinbase-login', 'coinbase-account', 'coinbase-pro', 'c0inbase'],
            'binance': ['binance-login', 'binance-account', 'binance-us', 'b1nance'],
            'kraken': ['kraken-login', 'kraken-account', 'kraken-pro', 'kr@ken'],
            'robinhood': ['robinhood-login', 'robinhood-account', 'robinhood-trading', 'r0binhood'],
            'metamask': ['metamask-login', 'metamask-wallet', 'metamask-extension', 'metam@sk'],
            # Government & Education
            'irs': ['irs-login', 'irs-gov', 'irs-account', '1rs', 'irs-tax'],
            'usps': ['usps-login', 'usps-tracking', 'usps-account', 'usp5', 'usps-com'],
            'fedex': ['fedex-login', 'fedex-tracking', 'fedex-account', 'fed3x'],
            'ups': ['ups-login', 'ups-tracking', 'ups-account', 'up5', 'up5-login'],
            'dhl': ['dhl-login', 'dhl-tracking', 'dhl-account', 'dh1', 'dh1-login'],
        }
        
        if brand in common_typos:
            for typo in common_typos[brand]:
                if typo in domain:
                    return True
        
        # Character substitution patterns
        substitutions = {
            'o': ['0', '○'],
            'i': ['1', 'l', '|', '!'],
            'l': ['1', 'i', '|', '!'],
            's': ['5', '$', 'z'],
            'e': ['3', '€'],
            'a': ['4', '@'],
            't': ['7', '+'],
            'b': ['8', '6'],
            'g': ['9', '6'],
            'z': ['2', 's']
        }
        
        # Check for character substitutions
        for original, substitutes in substitutions.items():
            for substitute in substitutes:
                altered_brand = brand.replace(original, substitute)
                if altered_brand in domain and altered_brand != brand:
                    return True
        
        # Check for hyphenated versions with action words
        action_words = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'id', 'password']
        for action in action_words:
            # Brand-action pattern
            if f"{brand}-{action}" in domain or f"{action}-{brand}" in domain:
                return True
            
            # Check with common typos
            for original, substitutes in substitutions.items():
                for substitute in substitutes:
                    altered_brand = brand.replace(original, substitute)
                    if f"{altered_brand}-{action}" in domain:
                        return True
        
        # Check for added/removed characters in brand name
        if len(brand) > 4:
            # Allow 1-2 character differences
            for i in range(len(domain) - len(brand) + 1):
                substring = domain[i:i+len(brand)]
                if substring in brand or brand in substring:
                    # Check if it's just the brand or a variation
                    if substring != brand:
                        # Count differences
                        differences = sum(1 for a, b in zip(substring, brand) if a != b)
                        if differences <= 2 and len(substring) >= len(brand) - 1:
                            return True
        
        return False
    
    def analyze_content_safely(self, url: str) -> int:
        """Safely analyze page content for phishing indicators"""
        score = 0
        max_retries = 2
        retry_delay = 1
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check if domain exists before trying to connect
        if not self.check_domain_exists(domain):
            self.findings.append("⚠️  Cannot analyze content: Domain does not exist")
            return score + 10  # Add some risk for non-existent domains
        
        # Skip content analysis for trusted domains
        is_trusted, trust_info = self.trusted_domains.is_trusted_domain(domain)
        if is_trusted:
            self.findings.append("✓ Skipping deep content scan for trusted domain")
            return score
        
        for attempt in range(max_retries):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                response = requests.get(url, headers=headers, timeout=10, verify=True, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 307, 308]:
                    # Don't penalize legitimate redirects too much
                    if response.status_code in [301, 308]:
                        status_msg = {301: 'Moved Permanently', 308: 'Permanent Redirect'}
                        self.findings.append(f"⚠️  HTTP {response.status_code} Redirect ({status_msg[response.status_code]})")
                        
                        if 'Location' in response.headers:
                            redirect_url = response.headers['Location']
                            display_url = redirect_url[:50] + '...' if len(redirect_url) > 50 else redirect_url
                            self.findings.append(f"⚠️  Redirects to: {display_url}")
                            self.detected_urls.append(redirect_url)
                    
                    try:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Check for login forms
                        login_forms = soup.find_all('form')
                        if login_forms:
                            form_count = 0
                            for form in login_forms:
                                inputs = form.find_all('input')
                                password_fields = [i for i in inputs if i.get('type') == 'password']
                                if password_fields:
                                    form_count += 1
                            
                            if form_count > 1:  # More than 1 login form is suspicious
                                self.findings.append(f"⚠️  {form_count} login forms with password fields detected")
                                score += min(form_count * 8, 25)
                        
                        # Check for urgency keywords
                        text_content = soup.get_text().lower()
                        urgency_count = 0
                        for keyword in self.suspicious_keywords:
                            if keyword in text_content:
                                count = text_content.count(keyword)
                                urgency_count += count
                        
                        if urgency_count > 8:  # Moderate threshold
                            self.findings.append(f"⚠️  {urgency_count} urgency/sensitive keywords detected")
                            score += min(urgency_count * 2, 30)
                        
                        # Check for fake browser warnings
                        fake_warnings = ['your browser is outdated', 'update your browser', 
                                       'install flash player', 'update flash player',
                                       'virus detected', 'security alert', 'java update',
                                       'adobe flash', 'click to update', 'critical update',
                                       'scan now', 'clean now', 'remove virus']
                        warning_count = 0
                        for warning in fake_warnings:
                            if warning in text_content:
                                warning_count += 1
                        
                        if warning_count > 0:
                            self.findings.append(f"❌ {warning_count} fake browser/security warning(s) detected")
                            score += min(warning_count * 15, 40)
                    
                    except Exception as e:
                        self.findings.append(f"⚠️  Content parsing error: {str(e)[:50]}...")
                
                elif response.status_code != 200:
                    self.findings.append(f"⚠️  HTTP Status: {response.status_code}")
                
                # Success - break retry loop
                break
                
            except requests.exceptions.SSLError:
                self.findings.append("⚠️  SSL certificate error")
                score += 10
                break
            
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                self.findings.append("⚠️  Request timeout")
                break
            
            except requests.exceptions.TooManyRedirects:
                self.findings.append("❌ Too many redirects (possible redirect loop)")
                score += 20
                break
            
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                self.findings.append(f"⚠️  Connection error: {str(e)[:50]}...")
                break
        
        return score
    
    def check_reputation_patterns(self, url: str) -> int:
        """Check for known phishing patterns"""
        score = 0
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Skip pattern check for trusted domains
        is_trusted, _ = self.trusted_domains.is_trusted_domain(domain)
        if is_trusted:
            return score
        
        # Patterns with higher penalties
        patterns = [
            (r'https?://[^/]+/login\.php\?redirect=', 30, "Suspicious login redirect pattern"),
            (r'https?://[^/]+/verify/[a-zA-Z0-9]{16,}', 25, "Generic verification URL with token"),
            (r'https?://[^/]+/account/update', 20, "Account update pattern"),
            (r'\?token=[a-zA-Z0-9]{32,}', 15, "Long token parameter"),
            (r'\?session=[a-zA-Z0-9]{24,}', 15, "Session parameter"),
            (r'/auth/realms/[^/]+/protocol/openid-connect', 10, "OpenID Connect endpoint"),
            (r'\.php\?action=(login|verify|confirm)', 20, "PHP action parameter"),
            (r'\.aspx\?ReturnUrl=', 15, "ASP.NET return URL"),
            (r'\.jsp\?page=(login|account)', 15, "JSP page parameter"),
            (r'\/wp-(login|admin)', 15, "WordPress login/admin page"),
            (r'\/admin(-panel)?\/login', 20, "Admin login page"),
            (r'\?return(to|url)=', 10, "Return URL parameter"),
            (r'\/signin.*\?continue=', 15, "Signin with continue parameter"),
        ]
        
        for pattern, pattern_score, message in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                self.findings.append(f"⚠️  {message}")
                score += pattern_score
        
        # Check for encoded characters
        if '%' in url:
            encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', url)
            encoded_count = len(encoded_parts)
            if encoded_count > 3:
                self.findings.append(f"⚠️  {encoded_count} URL-encoded characters")
                score += min(encoded_count * 3, 25)
        
        # Check for JavaScript in URL
        if 'javascript:' in url.lower():
            self.findings.append("❌ JavaScript code in URL")
            score += 40
        
        # Check for data URIs
        if url.lower().startswith('data:'):
            self.findings.append("❌ Data URI detected (possible malicious payload)")
            score += 35
        
        # Check for double extensions
        double_ext_pattern = r'\.(php|html|htm|asp|aspx|jsp)\.[a-z]{2,4}$'
        if re.search(double_ext_pattern, url, re.IGNORECASE):
            self.findings.append("❌ Double file extension detected")
            score += 30
        
        # Check for very long random strings in path
        random_pattern = r'/[a-f0-9]{32,}/'
        if re.search(random_pattern, url, re.IGNORECASE):
            self.findings.append("⚠️  Long random string in URL")
            score += 15
        
        return score
    
    def analyze_abused_infrastructure(self, url: str) -> int:
        """Check for abused legitimate infrastructure"""
        score = 0
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if domain matches abused infrastructure patterns
            is_abused, abuse_info = self.abused_infra.check_abused_infrastructure(domain)
            
            if is_abused:
                # High risk if it's a brand login on abused infrastructure
                extracted = tldextract.extract(url)
                domain_name = extracted.domain.lower()
                
                # Common brand names to check
                brand_names = ['facebook', 'google', 'microsoft', 'apple', 'paypal',
                              'amazon', 'netflix', 'instagram', 'twitter', 'linkedin',
                              'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc']
                
                # Check if domain contains brand name (typosquatting or exact)
                is_brand_related = any(brand in domain_name for brand in brand_names)
                
                if is_brand_related:
                    # Brand login on abused infrastructure = HIGH RISK
                    self.findings.append(f"❌ BRAND LOGIN ON ABUSED INFRASTRUCTURE: {abuse_info['category']}")
                    self.findings.append(f"⚠️  Description: {abuse_info['description']}")
                    score += abuse_info['risk_score'] + 25  # Extra penalty for brand abuse
                else:
                    # Generic site on abused infrastructure = MEDIUM RISK
                    self.findings.append(f"⚠️  Hosted on abused infrastructure: {abuse_info['category']}")
                    self.findings.append(f"ℹ️  Description: {abuse_info['description']}")
                    score += abuse_info['risk_score']
                
                # Additional checks for suspicious patterns in the domain
                if any(keyword in domain for keyword in ['login', 'secure', 'verify', 'auth']):
                    self.findings.append(f"⚠️  Suspicious keyword in abused domain")
                    score += 10
        
        except Exception as e:
            self.findings.append(f"⚠️  Abused infrastructure check failed: {str(e)[:50]}")
        
        return score
    
    def check_phishing_intelligence(self, url: str) -> int:
        """Check URL against phishing intelligence database"""
        score = 0
        
        if not self.phishing_intel:
            return score
        
        try:
            parsed = urlparse(url)
            subdomain = parsed.netloc.lower()
            
            # Check if subdomain is in phishing database
            is_in_database, intel_info = self.phishing_intel.check_subdomain_in_database(subdomain)
            
            if is_in_database:
                if intel_info.get('match_type') == 'exact':
                    # Exact subdomain match - HIGH RISK
                    self.findings.append(f"🚨 SUBDOMAIN IN PHISHING DATABASE: {intel_info.get('subdomain', 'N/A')}")
                    self.findings.append(f"📊 Source: {intel_info.get('source', 'Unknown')}")
                    self.findings.append(f"📈 Detections: {intel_info.get('detection_count', 0)} times")
                    self.findings.append(f"📅 First seen: {intel_info.get('first_seen', 'Unknown')}")
                    self.findings.append(f"📅 Last seen: {intel_info.get('last_seen', 'Unknown')}")
                    
                    # Calculate risk based on detection count and recency
                    base_score = min(intel_info.get('risk_score', 60), 80)
                    
                    # Add recency bonus
                    if 'last_seen' in intel_info and intel_info['last_seen']:
                        try:
                            last_seen_str = intel_info['last_seen'].replace('Z', '+00:00')
                            last_seen = datetime.fromisoformat(last_seen_str)
                            days_ago = (datetime.now() - last_seen).days
                            if days_ago < 7:  # Recently seen
                                base_score += 15
                            elif days_ago < 30:  # Seen in last month
                                base_score += 5
                        except:
                            pass  # If date parsing fails, skip recency bonus
                    
                    score += base_score
                
                elif intel_info.get('match_type') == 'domain':
                    # Domain-level match - MEDIUM RISK
                    self.findings.append(f"⚠️  DOMAIN IN PHISHING DATABASE: {intel_info.get('domain', 'N/A')}")
                    self.findings.append(f"📊 Sources: {', '.join(intel_info.get('sources', ['Unknown'])[:3])}")
                    self.findings.append(f"📈 Total detections: {intel_info.get('detection_count', 0)}")
                    self.findings.append(f"⚠️  Risk level: {intel_info.get('risk_level', 'medium')}")
                    
                    # Calculate risk based on detection count
                    risk_level = intel_info.get('risk_level', 'medium')
                    if risk_level == 'high':
                        base_score = 40
                    elif risk_level == 'medium':
                        base_score = 30
                    else:
                        base_score = 20
                    
                    detection_count = intel_info.get('detection_count', 0)
                    if detection_count > 10:
                        base_score += 10
                    elif detection_count > 5:
                        base_score += 5
                    
                    score += base_score
        
        except Exception as e:
            self.findings.append(f"⚠️  Phishing intelligence check failed: {str(e)[:50]}")
        
        return score
    
    def check_ip_reputation_for_url(self, url: str) -> Tuple[int, Optional[Dict]]:
        """Check IP reputation for the URL's resolved IP"""
        score = 0
        ip_reputation_data = None
        
        if not self.ip_intel:
            return score, ip_reputation_data
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Try to resolve the domain to IP
            try:
                # Remove port if present
                if ':' in domain:
                    domain = domain.split(':')[0]
                
                # Check if it's already an IP
                ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                if re.match(ip_pattern, domain):
                    ip_address = domain
                else:
                    # DNS resolution
                    ip_address = socket.gethostbyname(domain)
                
                # Check IP reputation
                ip_reputation = self.ip_intel.check_ip_reputation(ip_address)
                ip_reputation_data = ip_reputation
                
                # Adjust score based on IP reputation
                if ip_reputation['is_blacklisted']:
                    self.findings.append(f"❌ IP {ip_address} is BLACKLISTED in threat databases")
                    score += 35
                elif ip_reputation['threat_level'] == 'high':
                    self.findings.append(f"⚠️  IP {ip_address} has HIGH threat reputation")
                    score += 25
                elif ip_reputation['threat_level'] == 'medium':
                    self.findings.append(f"⚠️  IP {ip_address} has suspicious reputation")
                    score += 15
                elif ip_reputation['threat_level'] == 'safe':
                    self.findings.append(f"✓ IP {ip_address} appears safe")
                
                # Add reputation score to findings
                self.findings.append(f"📊 IP Reputation Score: {ip_reputation['score']}/100")
                
            except (socket.gaierror, socket.error):
                self.findings.append("⚠️  Could not resolve domain to IP for reputation check")
                score += 5
            except Exception as e:
                self.findings.append(f"⚠️  IP reputation check failed: {str(e)[:50]}")
        
        except Exception as e:
            self.findings.append(f"⚠️  IP reputation analysis error: {str(e)[:50]}")
        
        return score, ip_reputation_data
    
    def enhanced_typosquatting_check(self, domain: str) -> Tuple[bool, str, int]:
        """Enhanced typosquatting detection with brand database"""
        score = 0
        detected_brand = None
        
        # Extended brand database with common targets
        brand_database = {
            'facebook': ['faceb00k', 'facebok', 'facebook-login', 'fb-login', 'facebook-secure'],
            'google': ['goog1e', 'g00gle', 'google-login', 'accounts-google', 'google-verify'],
            'paypal': ['paypa1', 'paypal-login', 'paypal-secure', 'verify-paypal'],
            'microsoft': ['micr0soft', 'microsoft-login', 'office365-login', 'microsoft-verify'],
            'apple': ['app1e', 'apple-id', 'icloud-login', 'apple-verify'],
            'amazon': ['amaz0n', 'amazon-login', 'aws-login', 'amazon-verify'],
            'netflix': ['netf1ix', 'netflix-login', 'netflix-billing', 'netflix-update'],
            'instagram': ['instagrarn', 'instagram-login', 'insta-verify'],
            'twitter': ['tw1tter', 'twitter-login', 'twitter-verify'],
            'linkedin': ['1inkedin', 'linkedin-login', 'linkedin-jobs']
        }
        
        domain_lower = domain.lower()
        
        for brand, patterns in brand_database.items():
            # Check for exact brand in domain (not as part of another word)
            if f"{brand}." in domain_lower or domain_lower.endswith(brand):
                detected_brand = brand
                score += 30
                break
            
            # Check for patterns
            for pattern in patterns:
                if pattern in domain_lower:
                    detected_brand = brand
                    score += 35
                    break
            
            # Character substitution check
            substitutions = {
                'o': ['0'],
                'i': ['1', 'l'],
                'l': ['1', 'i'],
                's': ['5'],
                'e': ['3'],
                'a': ['4', '@'],
                't': ['7']
            }
            
            # Generate variations
            for original, substitutes in substitutions.items():
                for sub in substitutes:
                    modified_brand = brand.replace(original, sub)
                    if modified_brand in domain_lower:
                        detected_brand = brand
                        score += 40
                        break
        
        return detected_brand is not None, detected_brand, score
    
    def scan_single_url(self, url: str, show_progress: bool = True) -> Dict:
        """Enhanced URL scanning with phishing intelligence & IP reputation"""
        url_results = {
            'url': url,
            'url_details': {},
            'findings': [],
            'risk_score': 0,
            'safe_to_visit': True,
            'recommendation': '',
            'breakdown': {},
            'trusted_domain': False,
            'abused_infrastructure': False,
            'phishing_intelligence_match': False,
            'ip_reputation': None  # New field
        }
        
        # Get URL details
        url_results['url_details'] = self.get_url_details(url)
        
        # Perform multi-layer analysis
        steps = [
            ('Analyzing URL structure', self.analyze_url_structure),
            ('Analyzing domain', self.analyze_domain),
            ('Checking abused infrastructure', self.analyze_abused_infrastructure),
            ('Checking phishing intelligence', self.check_phishing_intelligence),
            ('Checking IP reputation', self.check_ip_reputation_for_url),  # New step
            ('Analyzing content', self.analyze_content_safely),
            ('Checking patterns', self.check_reputation_patterns)
        ]
        
        for i, (desc, func) in enumerate(steps, 1):
            if show_progress:
                print(f"\n{self.progress_bar.create_scan_progress(i, len(steps), desc + '...')}")
            
            if desc == 'Checking IP reputation':
                score, ip_data = func(url)
                url_results['breakdown']['ip_reputation'] = score
                url_results['risk_score'] += score
                url_results['ip_reputation'] = ip_data
            else:
                score = func(url)
                step_name = desc.lower().replace(' ', '_')
                url_results['breakdown'][step_name] = score
                url_results['risk_score'] += score
        
        # Apply trusted domain adjustment
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            is_trusted, trust_info = self.trusted_domains.is_trusted_domain(domain)
            url_results['trusted_domain'] = is_trusted
            
            if is_trusted:
                original_score = url_results['risk_score']
                adjusted_score = self.trusted_domains.adjust_risk_for_trusted_domain(domain, original_score)
                url_results['breakdown']['trust_adjustment'] = adjusted_score - original_score
                url_results['risk_score'] = adjusted_score
        except:
            pass
        
        # Check for abused infrastructure
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            is_abused, abuse_info = self.abused_infra.check_abused_infrastructure(domain)
            if is_abused:
                url_results['abused_infrastructure'] = True
                url_results['abuse_info'] = abuse_info
        except:
            pass
        
        # Check for phishing intelligence match
        try:
            parsed = urlparse(url)
            subdomain = parsed.netloc.lower()
            if self.phishing_intel:
                is_in_database, intel_info = self.phishing_intel.check_subdomain_in_database(subdomain)
                if is_in_database:
                    url_results['phishing_intelligence_match'] = True
                    url_results['intel_info'] = intel_info
        except:
            pass
        
        # Cap score at 100
        url_results['risk_score'] = min(url_results['risk_score'], 100)
        url_results['findings'] = self.findings.copy()
        
        # Enhanced recommendation
        if url_results['risk_score'] > 60:
            url_results['safe_to_visit'] = False
            if url_results.get('phishing_intelligence_match'):
                url_results['recommendation'] = '🚨 DO NOT VISIT - Known phishing domain'
            elif url_results.get('abused_infrastructure'):
                url_results['recommendation'] = 'DO NOT VISIT - Brand login on abused infrastructure'
            elif url_results.get('ip_reputation') and url_results['ip_reputation'].get('is_blacklisted'):
                url_results['recommendation'] = 'DO NOT VISIT - IP is blacklisted'
            else:
                url_results['recommendation'] = 'DO NOT VISIT - High risk of phishing'
        elif url_results['risk_score'] > 30:
            if url_results.get('phishing_intelligence_match'):
                url_results['recommendation'] = '🚨 HIGH CAUTION - Domain in phishing database'
            elif url_results.get('abused_infrastructure'):
                url_results['recommendation'] = 'EXTREME CAUTION - Suspicious infrastructure detected'
            elif url_results.get('ip_reputation') and url_results['ip_reputation'].get('threat_level') == 'high':
                url_results['recommendation'] = 'HIGH CAUTION - IP has poor reputation'
            else:
                url_results['recommendation'] = 'Visit with caution - Suspicious indicators'
        else:
            url_results['recommendation'] = 'Likely safe - No major indicators'
        
        return url_results
    
    def scan_url(self, url: str) -> Dict:
        """Main URL scanning function"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔍 Scanning URL: {Fore.WHITE if COLORS_ENABLED else ''}{url}")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        # Reset scanner
        self.reset_scanner()
        
        # Show animated scanning indicator
        self.progress_bar.show_animated_scanning("Starting analysis...")
        
        # Perform scan
        results = self.scan_single_url(url)
        
        # Add timestamp
        results['timestamp'] = datetime.now().isoformat()
        results['scanner_version'] = '1.8'
        
        return results