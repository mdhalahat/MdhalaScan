"""
MdhalaScan - Utilities Module
Contains common classes, constants, and helper functions
"""

import re
import colorsys
import random
import time
import hashlib
import ipaddress
import sqlite3
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import tldextract
from urllib.parse import urlparse

# Try to import colorama
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    COLORS_ENABLED = False

class TrustedDomains:
    """Manage trusted domains and whitelist"""
    
    # Major trusted domains with reasonable adjustments
    MAJOR_TRUSTED_DOMAINS = {
        # Social Media
        'facebook.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'fb.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'instagram.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'twitter.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'x.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'linkedin.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'tiktok.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'pinterest.com': {'category': 'Social Media', 'risk_adjustment': -15},
        'reddit.com': {'category': 'Social Media', 'risk_adjustment': -15},
        
        # Tech & Cloud
        'google.com': {'category': 'Tech', 'risk_adjustment': -15},
        'gmail.com': {'category': 'Tech', 'risk_adjustment': -15},
        'github.com': {'category': 'Tech', 'risk_adjustment': -15},
        'gitlab.com': {'category': 'Tech', 'risk_adjustment': -15},
        'microsoft.com': {'category': 'Tech', 'risk_adjustment': -15},
        'apple.com': {'category': 'Tech', 'risk_adjustment': -15},
        'amazon.com': {'category': 'Tech', 'risk_adjustment': -15},
        'aws.amazon.com': {'category': 'Tech', 'risk_adjustment': -15},
        'cloudflare.com': {'category': 'Tech', 'risk_adjustment': -15},
        
        # E-commerce & Payments
        'paypal.com': {'category': 'Payment', 'risk_adjustment': -15},
        'stripe.com': {'category': 'Payment', 'risk_adjustment': -15},
        'ebay.com': {'category': 'E-commerce', 'risk_adjustment': -15},
        'amazon.co.uk': {'category': 'E-commerce', 'risk_adjustment': -15},
        'amazon.de': {'category': 'E-commerce', 'risk_adjustment': -15},
        'shopify.com': {'category': 'E-commerce', 'risk_adjustment': -15},
        
        # Streaming & Entertainment
        'netflix.com': {'category': 'Entertainment', 'risk_adjustment': -15},
        'youtube.com': {'category': 'Entertainment', 'risk_adjustment': -15},
        'spotify.com': {'category': 'Entertainment', 'risk_adjustment': -15},
        'twitch.tv': {'category': 'Entertainment', 'risk_adjustment': -15},
        
        # Author's domains (moderate adjustment)
        'mdhalahat.com': {'category': 'Author', 'risk_adjustment': -20},
        'mdhalalearn.thinkific.com': {'category': 'Author', 'risk_adjustment': -20},
        
        # Government & Education
        'gov.uk': {'category': 'Government', 'risk_adjustment': -20},
        'gov.us': {'category': 'Government', 'risk_adjustment': -20},
        '.edu': {'category': 'Education', 'risk_adjustment': -15},  # TLD
        
        # Other trusted
        'wikipedia.org': {'category': 'Reference', 'risk_adjustment': -15},
        'stackoverflow.com': {'category': 'Tech', 'risk_adjustment': -15},
        'medium.com': {'category': 'Blogging', 'risk_adjustment': -10},
    }
    
    # Trusted TLDs
    TRUSTED_TLDS = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.de', '.fr', '.tn']
    
    @classmethod
    def is_trusted_domain(cls, domain: str) -> Tuple[bool, Optional[Dict]]:
        """Check if a domain is in the trusted list"""
        domain = domain.lower().strip()
        
        # Check exact match
        if domain in cls.MAJOR_TRUSTED_DOMAINS:
            return True, cls.MAJOR_TRUSTED_DOMAINS[domain]
        
        # Check subdomains of trusted domains
        for trusted_domain, info in cls.MAJOR_TRUSTED_DOMAINS.items():
            if domain.endswith('.' + trusted_domain):
                return True, info
        
        # Check for trusted TLDs
        for tld in cls.TRUSTED_TLDS:
            if domain.endswith(tld):
                # For .edu TLD, automatically trusted
                if tld == '.edu':
                    return True, {'category': 'Education', 'risk_adjustment': -15}
                # For .gov domains, trusted
                if tld in ['.gov', '.gov.uk', '.gov.us']:
                    return True, {'category': 'Government', 'risk_adjustment': -20}
        
        return False, None
    
    @classmethod
    def adjust_risk_for_trusted_domain(cls, domain: str, current_score: int) -> int:
        """Adjust risk score for trusted domains"""
        is_trusted, info = cls.is_trusted_domain(domain)
        if is_trusted and info:
            adjusted = current_score + info['risk_adjustment']
            return max(0, adjusted)  # Don't go below 0
        return current_score

class AbusedInfrastructureDB:
    """Database of commonly abused legitimate services"""
    
    def __init__(self, db_path: str = "abused_infra.db"):
        self.db_path = db_path
        
        # Define abused patterns FIRST
        self.abused_patterns = {
            # 🔴 HIGH RISK - Commonly abused platforms
            'cloud_tunnel': {
                'patterns': [
                    r'.*\.trycloudflare\.com$',
                    r'.*\.cloudflared\.net$',
                    r'.*\.ngrok\.(io|free\.app)$',
                    r'.*\.loca\.lt$',
                    r'.*\.serveo\.net$',
                    r'.*\.beget\.app$',
                    r'.*\.localtunnel\.me$'
                ],
                'category': 'Cloud Tunnel Service',
                'risk_score': 25,
                'description': 'Temporary cloud tunnel - commonly abused for phishing'
            },
            
            'static_site': {
                'patterns': [
                    r'.*\.github\.io$',
                    r'.*\.vercel\.app$',
                    r'.*\.netlify\.app$',
                    r'.*\.pages\.dev$',
                    r'.*\.web\.app$',
                    r'.*\.firebaseapp\.com$',
                    r'.*\.surge\.sh$',
                    r'.*\.gitlab\.io$',
                    r'.*\.herokuapp\.com$',
                    r'.*\.azurewebsites\.net$',
                    r'.*\.onrender\.com$',
                    r'.*\.fly\.dev$',
                    r'.*\.railway\.app$'
                ],
                'category': 'Static Site/Dev Platform',
                'risk_score': 20,
                'description': 'Legitimate dev platform - suspicious for brand login pages'
            },
            
            'free_website': {
                'patterns': [
                    r'.*\.weebly\.com$',
                    r'.*\.wixsite\.com$',
                    r'.*\.wordpress\.com$',
                    r'.*\.blogspot\.(com|[a-z]{2,3})$',
                    r'.*\.sites\.google\.com$',
                    r'.*\.webnode\.([a-z]{2,3})$',
                    r'.*\.000webhostapp\.com$',
                    r'.*\.my-free\.website$'
                ],
                'category': 'Free Website Builder',
                'risk_score': 22,
                'description': 'Free website builder - commonly used in phishing kits'
            },
            
            'cloud_storage': {
                'patterns': [
                    r'.*\.s3\.amazonaws\.com$',
                    r'.*\.blob\.core\.windows\.net$',
                    r'.*\.storage\.googleapis\.com$',
                    r'drive\.google\.com$',
                    r'.*\.dropboxusercontent\.com$',
                    r'.*\.sharepoint\.com$',
                    r'.*\.onedrive\.live\.com$'
                ],
                'category': 'Cloud Storage Abuse',
                'risk_score': 18,
                'description': 'Cloud storage - suspicious for hosting fake documents/forms'
            },
            
            'email_platform': {
                'patterns': [
                    r'.*\.mailchimp\.com$',
                    r'.*\.sendgrid\.net$',
                    r'.*\.campaign-archive\.com$',
                    r'.*\.mailerlite\.com$',
                    r'.*\.mailerpage\.com$',
                    r'.*\.constantcontact\.com$'
                ],
                'category': 'Email/Marketing Platform',
                'risk_score': 15,
                'description': 'Email marketing platform - abused for phishing campaigns'
            },
            
            'dynamic_dns': {
                'patterns': [
                    r'.*\.duckdns\.org$',
                    r'.*\.no-ip\.(org|com|net)$',
                    r'.*\.ddns\.net$',
                    r'.*\.dynu\.(net|com)$',
                    r'.*\.freedns\.afraid\.org$',
                    r'.*\.dyn\.com$',
                    r'.*\.myftp\.org$',
                    r'.*\.hopto\.org$'
                ],
                'category': 'Dynamic DNS Service',
                'risk_score': 28,
                'description': 'Dynamic DNS - very popular with malware & phishing'
            },
            
            # 🟠 MEDIUM RISK - Suspicious but not always malicious
            'url_shortener': {
                'patterns': [
                    r'.*\.bit\.ly$',
                    r'.*\.tinyurl\.com$',
                    r'.*\.goo\.gl$',
                    r'.*\.ow\.ly$',
                    r'.*\.is\.gd$',
                    r'.*\.buff\.ly$',
                    r'.*\.t\.co$',
                    r'.*\.cutt\.ly$',
                    r'.*\.shorturl\.at$'
                ],
                'category': 'URL Shortener',
                'risk_score': 12,
                'description': 'URL shortener - can hide malicious destinations'
            }
        }
        
        # Now initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create abused patterns table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS abused_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE,
            category TEXT,
            risk_score INTEGER,
            description TEXT,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create suspicious domains table (dynamic)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            detected_at TIMESTAMP,
            source_pattern_id INTEGER,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (source_pattern_id) REFERENCES abused_patterns (id)
        )
        ''')
        
        # Create threat intelligence feeds table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT,
            feed_url TEXT,
            last_fetched TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create update history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            update_type TEXT,
            items_added INTEGER,
            items_removed INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Insert default patterns if not exists
        self.insert_default_patterns(cursor)
        
        # Insert default threat feeds
        self.insert_default_feeds(cursor)
        
        conn.commit()
        conn.close()
    
    def insert_default_patterns(self, cursor):
        """Insert default abused infrastructure patterns"""
        for category, data in self.abused_patterns.items():
            for pattern in data['patterns']:
                try:
                    cursor.execute('''
                    INSERT OR IGNORE INTO abused_patterns 
                    (pattern, category, risk_score, description, source)
                    VALUES (?, ?, ?, ?, ?)
                    ''', (pattern, data['category'], data['risk_score'], 
                         data['description'], 'builtin'))
                except:
                    pass
    
    def insert_default_feeds(self, cursor):
        """Insert default threat intelligence feeds"""
        feeds = [
            ('PhishTank', 'http://data.phishtank.com/data/online-valid.json', 1),
            ('OpenPhish', 'https://openphish.com/feed.txt', 1),
            ('URLhaus', 'https://urlhaus.abuse.ch/downloads/text_online/', 1),
            ('Abuse.ch SSL Blacklist', 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv', 1)
        ]
        
        for feed_name, feed_url, is_active in feeds:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO threat_feeds (feed_name, feed_url, is_active)
                VALUES (?, ?, ?)
                ''', (feed_name, feed_url, is_active))
            except:
                pass
    
    def check_abused_infrastructure(self, domain: str) -> Tuple[bool, Dict]:
        """Check if domain matches abused infrastructure patterns"""
        # Check hardcoded patterns first (fast)
        for category, data in self.abused_patterns.items():
            for pattern in data['patterns']:
                if re.match(pattern, domain):
                    result = {
                        'is_abused': True,
                        'category': data['category'],
                        'risk_score': data['risk_score'],
                        'description': data['description'],
                        'matched_pattern': pattern
                    }
                    return True, result
        
        # Check database patterns
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT pattern, category, risk_score, description FROM abused_patterns')
        patterns = cursor.fetchall()
        
        for pattern, category, risk_score, description in patterns:
            if re.match(pattern, domain):
                result = {
                    'is_abused': True,
                    'category': category,
                    'risk_score': risk_score,
                    'description': description,
                    'matched_pattern': pattern
                }
                conn.close()
                return True, result
        
        conn.close()
        return False, {}
    
    def add_suspicious_domain(self, domain: str, pattern_id: int):
        """Add a detected suspicious domain to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO suspicious_domains 
            (domain, detected_at, source_pattern_id)
            VALUES (?, CURRENT_TIMESTAMP, ?)
            ''', (domain, pattern_id))
            conn.commit()
        except Exception as e:
            print(f"Error adding domain {domain}: {e}")
        finally:
            conn.close()
    
    def get_recent_suspicious_domains(self, days: int = 7) -> List[Dict]:
        """Get recently detected suspicious domains"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT d.domain, d.detected_at, p.category, p.description
        FROM suspicious_domains d
        JOIN abused_patterns p ON d.source_pattern_id = p.id
        WHERE d.detected_at >= datetime('now', ?)
        ORDER BY d.detected_at DESC
        LIMIT 50
        ''', (f'-{days} days',))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'domain': row[0],
                'detected_at': row[1],
                'category': row[2],
                'description': row[3]
            })
        
        conn.close()
        return results
    
    def update_patterns_from_web(self):
        """Fetch and update patterns from online sources"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}🔄 Updating abused infrastructure patterns...")
        
        new_patterns = []
        
        # Source 1: GitHub community lists
        try:
            response = requests.get(
                "https://raw.githubusercontent.com/antiphishing/Anti-Phishing/master/data/abused_domains.txt",
                timeout=10
            )
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        new_patterns.append({
                            'pattern': line.strip(),
                            'category': 'Community Reported',
                            'risk_score': 20,
                            'description': 'Community reported abused domain',
                            'source': 'github_antiphishing'
                        })
        except:
            pass
        
        # Source 2: Phishing database patterns
        try:
            response = requests.get(
                "https://phishstats.info/phish_score.json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for item in data.get('patterns', []):
                    if 'domain' in item:
                        new_patterns.append({
                            'pattern': item['domain'],
                            'category': item.get('type', 'Unknown'),
                            'risk_score': 25,
                            'description': 'PhishStats detected pattern',
                            'source': 'phishstats'
                        })
        except:
            pass
        
        # Update database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        added = 0
        for pattern_data in new_patterns:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO abused_patterns 
                (pattern, category, risk_score, description, source)
                VALUES (?, ?, ?, ?, ?)
                ''', (pattern_data['pattern'], pattern_data['category'],
                     pattern_data['risk_score'], pattern_data['description'],
                     pattern_data['source']))
                added += 1
            except:
                pass
        
        # Log update
        cursor.execute('''
        INSERT INTO update_history (update_type, items_added)
        VALUES (?, ?)
        ''', ('pattern_update', added))
        
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Updated {added} new patterns")
        return added

class ProgressBar:
    """Visual progress bar for risk scores"""
    
    @staticmethod
    def create_risk_bar(score: int, width: int = 50) -> str:
        """Create a visual progress bar for risk score"""
        filled = int(width * score / 100)
        empty = width - filled
        
        # Determine color based on risk level
        if score <= 30:
            color = Fore.GREEN if COLORS_ENABLED else ''
            label = "SAFE"
        elif score <= 60:
            color = Fore.YELLOW if COLORS_ENABLED else ''
            label = "SUSPICIOUS"
        else:
            color = Fore.RED if COLORS_ENABLED else ''
            label = "HIGH RISK"
        
        # Create bar
        bar = f"{color}{'█' * filled}{Fore.WHITE if COLORS_ENABLED else ''}{'░' * empty}"
        
        # Show percentage before label
        return f"[{bar}] {color}({score}% Risk) {label}{Style.RESET_ALL if COLORS_ENABLED else ''}"
    
    @staticmethod
    def create_scan_progress(step: int, total: int, description: str) -> str:
        """Create a progress indicator for scanning steps"""
        percentage = int((step / total) * 100)
        bar_width = 30
        filled = int(bar_width * percentage / 100)
        empty = bar_width - filled
        
        bar = f"{Fore.CYAN if COLORS_ENABLED else ''}{'█' * filled}{Fore.WHITE if COLORS_ENABLED else ''}{'░' * empty}"
        
        return f"{Fore.CYAN if COLORS_ENABLED else ''}[{bar}] {percentage}% {Fore.WHITE if COLORS_ENABLED else ''}{description}"
    
    @staticmethod
    def show_animated_scanning(message: str, duration: float = 1.5):
        """Show animated scanning indicator"""
        animation = "⣾⣽⣻⢿⡿⣟⣯⣷"
        start_time = time.time()
        i = 0
        
        try:
            while time.time() - start_time < duration:
                print(f"\r{Fore.CYAN if COLORS_ENABLED else ''}{animation[i % len(animation)]} {message}", end="", flush=True)
                time.sleep(0.1)
                i += 1
            print("\r" + " " * (len(message) + 10), end="\r")  # Clear line
        except KeyboardInterrupt:
            pass

# Common constants used across modules
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure',
    'update', 'confirm', 'password', 'banking', 'wallet',
    'urgent', 'immediate', 'required', 'suspended',
    'locked', 'restricted', 'verification', 'authorize',
    'security', 'authenticate', 'validate', 'recover',
    'reset', 'change', 'update', 'billing', 'payment'
]

HIGH_RISK_TLDS = ['.xyz', '.top', '.club', '.online', '.site', 
                  '.website', '.space', '.icu', '.review', '.date',
                  '.biz', '.info', '.click', '.stream', '.download',
                  '.win', '.bid', '.trade', '.science', '.racing']

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 't.co', 'bit.do', 'shorte.st', 'ow.ly',
    'shorturl.at', 'cutt.ly', 'shrinke.me', 'tiny.cc'
]

BRAND_NAMES = [
    'paypal', 'microsoft', 'apple', 'google', 'facebook',
    'amazon', 'netflix', 'bankofamerica', 'wellsfargo',
    'chase', 'citibank', 'hsbc', 'barclays', 'linkedin',
    'twitter', 'instagram', 'whatsapp', 'dropbox', 'adobe',
    'pinterest', 'pintrest', 'paypa1', 'g00gle', 'app1e',
    'paypaI', 'faceb00k', 'micr0soft', 'amaz0n', 'appIe'
]

SUSPICIOUS_PATTERNS = [
    (r'^[a-f0-9]{8,}$', 20, "Random-looking domain name"),
    (r'^[0-9]{6,}$', 15, "Numeric-only domain"),
    (r'^[a-z]{1,3}[0-9]{3,}$', 10, "Short letters followed by numbers"),
]