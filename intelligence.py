"""
MdhalaScan - Phishing Intelligence Database Module
Web scraping and database for phishing subdomains intelligence
"""

import re
import json
import sqlite3
import os
import random
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set, Any
from urllib.parse import urlparse

# Import from utils for color handling
try:
    from colorama import Fore, Style
    COLORS_ENABLED = True
except ImportError:
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    COLORS_ENABLED = False

class PhishingIntelligenceDB:
    """Web scraping and database for phishing subdomains intelligence"""
    
    def __init__(self, db_path: str = "phishing_intel.db"):
        self.db_path = db_path
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
        ]
        
        # Define scraping sources with priorities
        self.scraping_sources = {
            'phishing_database': {
                'url': 'https://phishtank.org/developer_info.php',
                'format': 'json',
                'active': True,
                'priority': 1,
                'description': 'PhishTank - Community phishing database',
                'api_key_required': False
            },
            'openphish': {
                'url': 'https://openphish.com/feed.txt',
                'format': 'text',
                'active': True,
                'priority': 1,
                'description': 'OpenPhish - Live phishing feeds',
                'api_key_required': False
            },
            'urlhaus': {
                'url': 'https://urlhaus.abuse.ch/downloads/text_online/',
                'format': 'text',
                'active': True,
                'priority': 2,
                'description': 'URLhaus - Malware distribution sites',
                'api_key_required': False
            },
            'phishstats': {
                'url': 'https://phishstats.info/phish_score.json',
                'format': 'json',
                'active': True,
                'priority': 2,
                'description': 'PhishStats - Phishing statistics',
                'api_key_required': False
            },
            'phishfort': {
                'url': 'https://github.com/phishfort/phishfort-lists/blob/master/blacklists/domains.json',
                'format': 'json',
                'active': True,
                'priority': 3,
                'description': 'PhishFort - Crypto phishing domains',
                'api_key_required': False
            },
            'cert_pl': {
                'url': 'https://hole.cert.pl/domains/domains.txt',
                'format': 'text',
                'active': True,
                'priority': 2,
                'description': 'CERT-PL - Malicious domains list',
                'api_key_required': False
            }
        }
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for phishing intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create scraped subdomains table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scraped_subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain TEXT UNIQUE,
            full_url TEXT,
            source_id INTEGER,
            category TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detection_count INTEGER DEFAULT 1,
            is_active BOOLEAN DEFAULT 1,
            risk_score INTEGER DEFAULT 50,
            tags TEXT,
            notes TEXT,
            FOREIGN KEY (source_id) REFERENCES scraping_sources (id)
        )
        ''')
        
        # Create scraping sources table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scraping_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT UNIQUE,
            source_url TEXT,
            format TEXT,
            is_active BOOLEAN DEFAULT 1,
            priority INTEGER DEFAULT 3,
            description TEXT,
            last_scraped TIMESTAMP,
            total_records INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0
        )
        ''')
        
        # Create scraping history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scraping_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            records_added INTEGER DEFAULT 0,
            records_updated INTEGER DEFAULT 0,
            records_failed INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            FOREIGN KEY (source_id) REFERENCES scraping_sources (id)
        )
        ''')
        
        # Create domain statistics table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            detection_count INTEGER DEFAULT 0,
            first_detected TIMESTAMP,
            last_detected TIMESTAMP,
            sources TEXT,
            risk_level TEXT DEFAULT 'medium',
            is_blocked BOOLEAN DEFAULT 0
        )
        ''')
        
        # Create pattern matching table for manual updates
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE,
            category TEXT,
            risk_score INTEGER DEFAULT 30,
            description TEXT,
            created_by TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Insert default scraping sources if not exists
        self.insert_default_sources(cursor)
        
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Phishing Intelligence Database initialized")
    
    def insert_default_sources(self, cursor):
        """Insert default scraping sources"""
        for source_name, source_info in self.scraping_sources.items():
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO scraping_sources 
                (source_name, source_url, format, is_active, priority, description)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    source_name,
                    source_info['url'],
                    source_info['format'],
                    source_info['active'],
                    source_info['priority'],
                    source_info['description']
                ))
            except Exception as e:
                print(f"Error inserting source {source_name}: {e}")
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent for web scraping"""
        return random.choice(self.user_agents)
    
    def fetch_from_source(self, source_name: str) -> Tuple[bool, List[str], str]:
        """Fetch data from a specific source"""
        if source_name not in self.scraping_sources:
            return False, [], f"Source '{source_name}' not found"
        
        source = self.scraping_sources[source_name]
        urls_found = []
        
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            print(f"  Fetching from {source_name}...")
            response = requests.get(source['url'], headers=headers, timeout=30, verify=True)
            
            if response.status_code != 200:
                return False, [], f"HTTP {response.status_code} - {response.reason}"
            
            if source['format'] == 'text':
                # Parse text format (one URL per line)
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract URLs and subdomains
                        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', line)
                        for url in urls:
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    urls_found.append({
                                        'subdomain': parsed.netloc,
                                        'full_url': url,
                                        'source': source_name
                                    })
                            except:
                                continue
            
            elif source['format'] == 'json':
                # Parse JSON format
                try:
                    data = response.json()
                    # Different JSON structures for different sources
                    if source_name == 'phishstats':
                        for item in data:
                            if 'url' in item:
                                url = item['url']
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    urls_found.append({
                                        'subdomain': parsed.netloc,
                                        'full_url': url,
                                        'source': source_name
                                    })
                    else:
                        # Generic JSON parsing
                        self.extract_urls_from_json(data, urls_found, source_name)
                except json.JSONDecodeError:
                    # Try alternative parsing
                    lines = response.text.split('\n')
                    for line in lines:
                        if line.strip():
                            urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', line)
                            for url in urls:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    urls_found.append({
                                        'subdomain': parsed.netloc,
                                        'full_url': url,
                                        'source': source_name
                                    })
            
            return True, urls_found, f"Successfully fetched {len(urls_found)} URLs"
            
        except requests.exceptions.Timeout:
            return False, [], "Request timeout"
        except requests.exceptions.ConnectionError:
            return False, [], "Connection error"
        except Exception as e:
            return False, [], f"Error: {str(e)}"
    
    def extract_urls_from_json(self, data: Any, urls_found: List, source_name: str):
        """Recursively extract URLs from JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ['url', 'domain', 'hostname', 'phish_url', 'link']:
                    if isinstance(value, str) and value.startswith(('http://', 'https://')):
                        parsed = urlparse(value)
                        if parsed.netloc:
                            urls_found.append({
                                'subdomain': parsed.netloc,
                                'full_url': value,
                                'source': source_name
                            })
                elif isinstance(value, (dict, list)):
                    self.extract_urls_from_json(value, urls_found, source_name)
        elif isinstance(data, list):
            for item in data:
                self.extract_urls_from_json(item, urls_found, source_name)
    
    def normalize_subdomain(self, subdomain: str) -> str:
        """Normalize subdomain by removing www and port numbers"""
        # Remove www prefix
        if subdomain.startswith('www.'):
            subdomain = subdomain[4:]
        
        # Remove port number
        if ':' in subdomain:
            subdomain = subdomain.split(':')[0]
        
        return subdomain.lower().strip()
    
    def run_scraping(self, sources: Optional[List[str]] = None, max_urls_per_source: int = 1000) -> Dict:
        """Run web scraping from specified sources"""
        if sources is None:
            sources = [s for s in self.scraping_sources.keys() if self.scraping_sources[s]['active']]
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🌐 WEB SCRAPING PHISHING SUBDOMAINS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        total_added = 0
        total_updated = 0
        source_results = {}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for source_name in sources:
            print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}[{source_name.upper()}]")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Source: {self.scraping_sources[source_name]['description']}")
            
            # Create scraping history entry
            cursor.execute('''
            INSERT INTO scraping_history (source_id, started_at, status)
            SELECT id, CURRENT_TIMESTAMP, 'running' 
            FROM scraping_sources WHERE source_name = ?
            ''', (source_name,))
            history_id = cursor.lastrowid
            
            # Fetch data from source
            success, urls, message = self.fetch_from_source(source_name)
            
            if not success:
                print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed: {message}")
                cursor.execute('''
                UPDATE scraping_history 
                SET completed_at = CURRENT_TIMESTAMP, 
                    status = 'failed',
                    error_message = ?
                WHERE id = ?
                ''', (message, history_id))
                continue
            
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Fetched {len(urls)} URLs")
            
            # Process and store URLs
            added = 0
            updated = 0
            failed = 0
            
            for url_data in urls[:max_urls_per_source]:
                try:
                    subdomain = self.normalize_subdomain(url_data['subdomain'])
                    
                    # Check if subdomain already exists
                    cursor.execute('SELECT id, detection_count FROM scraped_subdomains WHERE subdomain = ?', (subdomain,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Update existing entry
                        subdomain_id, count = existing
                        cursor.execute('''
                        UPDATE scraped_subdomains 
                        SET last_seen = CURRENT_TIMESTAMP, 
                            detection_count = detection_count + 1,
                            source_id = (SELECT id FROM scraping_sources WHERE source_name = ?)
                        WHERE id = ?
                        ''', (source_name, subdomain_id))
                        updated += 1
                    else:
                        # Insert new entry
                        cursor.execute('''
                        INSERT INTO scraped_subdomains 
                        (subdomain, full_url, source_id, category, risk_score, tags)
                        VALUES (?, ?, 
                            (SELECT id FROM scraping_sources WHERE source_name = ?),
                            ?, ?, ?)
                        ''', (
                            subdomain,
                            url_data['full_url'],
                            source_name,
                            'phishing',
                            60,  # Default risk score for scraped domains
                            source_name
                        ))
                        added += 1
                        
                        # Update domain statistics
                        domain = '.'.join(subdomain.split('.')[-2:])  # Get main domain
                        cursor.execute('''
                        INSERT OR REPLACE INTO domain_statistics 
                        (domain, detection_count, first_detected, last_detected, sources)
                        VALUES (?, 
                            COALESCE((SELECT detection_count + 1 FROM domain_statistics WHERE domain = ?), 1),
                            COALESCE((SELECT first_detected FROM domain_statistics WHERE domain = ?), CURRENT_TIMESTAMP),
                            CURRENT_TIMESTAMP,
                            COALESCE((SELECT sources || ', ' || ? FROM domain_statistics WHERE domain = ?), ?)
                        )
                        ''', (domain, domain, domain, source_name, domain, source_name))
                
                except Exception as e:
                    failed += 1
                    continue
            
            # Update scraping history
            cursor.execute('''
            UPDATE scraping_history 
            SET completed_at = CURRENT_TIMESTAMP, 
                status = 'completed',
                records_added = ?,
                records_updated = ?,
                records_failed = ?
            WHERE id = ?
            ''', (added, updated, failed, history_id))
            
            # Update source statistics
            cursor.execute('''
            UPDATE scraping_sources 
            SET last_scraped = CURRENT_TIMESTAMP,
                total_records = total_records + ? + ?
            WHERE source_name = ?
            ''', (added, updated, source_name))
            
            source_results[source_name] = {
                'added': added,
                'updated': updated,
                'failed': failed,
                'message': message
            }
            
            total_added += added
            total_updated += updated
            
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  Added: {added}, Updated: {updated}, Failed: {failed}")
        
        conn.commit()
        conn.close()
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}📊 SCRAPING SUMMARY")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}Total Added: {total_added}")
        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Total Updated: {total_updated}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Sources Processed: {len(sources)}")
        
        return {
            'total_added': total_added,
            'total_updated': total_updated,
            'sources_processed': len(sources),
            'source_results': source_results
        }
    
    def get_database_statistics(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Get total subdomains
        cursor.execute('SELECT COUNT(*) FROM scraped_subdomains')
        stats['total_subdomains'] = cursor.fetchone()[0]
        
        # Get active subdomains
        cursor.execute('SELECT COUNT(*) FROM scraped_subdomains WHERE is_active = 1')
        stats['active_subdomains'] = cursor.fetchone()[0]
        
        # Get subdomains by source
        cursor.execute('''
        SELECT s.source_name, COUNT(ss.id) as count
        FROM scraping_sources s
        LEFT JOIN scraped_subdomains ss ON s.id = ss.source_id
        GROUP BY s.source_name
        ORDER BY count DESC
        ''')
        stats['by_source'] = dict(cursor.fetchall())
        
        # Get recent activity
        cursor.execute('''
        SELECT DATE(last_seen) as date, COUNT(*) as count
        FROM scraped_subdomains
        WHERE last_seen >= date('now', '-30 days')
        GROUP BY DATE(last_seen)
        ORDER BY date DESC
        LIMIT 10
        ''')
        stats['recent_activity'] = cursor.fetchall()
        
        # Get top domains
        cursor.execute('''
        SELECT 
            CASE 
                WHEN INSTR(subdomain, '.') > 0 THEN 
                    SUBSTR(subdomain, INSTR(subdomain, '.') + 1)
                ELSE subdomain
            END as domain,
            COUNT(*) as count
        FROM scraped_subdomains
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
        ''')
        stats['top_domains'] = cursor.fetchall()
        
        # Get scraping history summary
        cursor.execute('''
        SELECT 
            COUNT(*) as total_scrapes,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            MAX(started_at) as last_scrape
        FROM scraping_history
        ''')
        row = cursor.fetchone()
        stats['scraping_summary'] = {
            'total_scrapes': row[0],
            'successful': row[1],
            'failed': row[2],
            'last_scrape': row[3]
        }
        
        conn.close()
        return stats
    
    def get_scraping_history(self, limit: int = 20) -> List[Dict]:
        """Get recent scraping history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT 
            h.id,
            s.source_name,
            h.started_at,
            h.completed_at,
            h.records_added,
            h.records_updated,
            h.status,
            h.error_message
        FROM scraping_history h
        JOIN scraping_sources s ON h.source_id = s.id
        ORDER BY h.started_at DESC
        LIMIT ?
        ''', (limit,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'id': row[0],
                'source': row[1],
                'started': row[2],
                'completed': row[3],
                'added': row[4],
                'updated': row[5],
                'status': row[6],
                'error': row[7]
            })
        
        conn.close()
        return history
    
    def add_custom_pattern(self, pattern: str, category: str, risk_score: int = 30, 
                          description: str = "", created_by: str = "user") -> bool:
        """Add a custom pattern manually"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT OR REPLACE INTO custom_patterns 
            (pattern, category, risk_score, description, created_by)
            VALUES (?, ?, ?, ?, ?)
            ''', (pattern, category, risk_score, description, created_by))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding pattern: {e}")
            return False
    
    def get_top_detected_domains(self, limit: int = 20) -> List[Dict]:
        """Get top detected domains"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT 
            domain,
            detection_count,
            first_detected,
            last_detected,
            sources,
            risk_level
        FROM domain_statistics
        ORDER BY detection_count DESC
        LIMIT ?
        ''', (limit,))
        
        domains = []
        for row in cursor.fetchall():
            domains.append({
                'domain': row[0],
                'detection_count': row[1],
                'first_detected': row[2],
                'last_detected': row[3],
                'sources': row[4].split(', ') if row[4] else [],
                'risk_level': row[5]
            })
        
        conn.close()
        return domains
    
    def check_subdomain_in_database(self, subdomain: str) -> Tuple[bool, Dict]:
        """Check if a subdomain exists in the phishing database"""
        normalized = self.normalize_subdomain(subdomain)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check exact match
        cursor.execute('''
        SELECT ss.subdomain, ss.full_url, ss.detection_count, ss.first_seen, ss.last_seen,
               s.source_name, ss.risk_score, ss.tags
        FROM scraped_subdomains ss
        JOIN scraping_sources s ON ss.source_id = s.id
        WHERE ss.subdomain = ? AND ss.is_active = 1
        ''', (normalized,))
        
        result = cursor.fetchone()
        
        if result:
            conn.close()
            return True, {
                'subdomain': result[0],
                'full_url': result[1],
                'detection_count': result[2],
                'first_seen': result[3],
                'last_seen': result[4],
                'source': result[5],
                'risk_score': result[6],
                'tags': result[7],
                'match_type': 'exact'
            }
        
        # Check domain-level match (e.g., check main domain)
        domain_parts = normalized.split('.')
        if len(domain_parts) >= 2:
            main_domain = '.'.join(domain_parts[-2:])
            
            cursor.execute('''
            SELECT ds.domain, ds.detection_count, ds.first_detected, ds.last_detected,
                   ds.sources, ds.risk_level
            FROM domain_statistics ds
            WHERE ds.domain = ?
            ''', (main_domain,))
            
            result = cursor.fetchone()
            
            if result:
                conn.close()
                return True, {
                    'domain': result[0],
                    'detection_count': result[1],
                    'first_detected': result[2],
                    'last_detected': result[3],
                    'sources': result[4].split(', ') if result[4] else [],
                    'risk_level': result[5],
                    'match_type': 'domain'
                }
        
        conn.close()
        return False, {}