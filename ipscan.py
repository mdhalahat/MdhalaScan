"""
MdhalaScan - IP Intelligence Database Module
IP reputation and threat intelligence
"""

import re
import json
import sqlite3
import os
import ipaddress
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# Import from utils for color handling
try:
    from colorama import Fore, Style
    COLORS_ENABLED = True
except ImportError:
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    COLORS_ENABLED = False

class IPIntelligenceDB:
    """Database for IP reputation and threat intelligence"""
    
    def __init__(self, db_path: str = "ip_intelligence.db"):
        self.db_path = db_path
        
        # Define IP intelligence sources
        self.ip_sources = {
            'abuseipdb': {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'type': 'api',
                'active': True,
                'description': 'AbuseIPDB - IP reputation database',
                'api_key_required': True
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/api/v3/ip_addresses/',
                'type': 'api',
                'active': True,
                'description': 'VirusTotal - IP analysis',
                'api_key_required': True
            },
            'ipqualityscore': {
                'url': 'https://ipqualityscore.com/api/json/ip/',
                'type': 'api',
                'active': False,  # Requires API key
                'description': 'IPQualityScore - Fraud prevention',
                'api_key_required': True
            },
            'threatfox': {
                'url': 'https://threatfox.abuse.ch/export/json/ip/',
                'type': 'feed',
                'active': True,
                'description': 'ThreatFox IP threat feed',
                'api_key_required': False
            },
            'firehol': {
                'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'type': 'feed',
                'active': True,
                'description': 'FireHOL Level 1 blocklist',
                'api_key_required': False
            },
            'spamhaus_drop': {
                'url': 'https://www.spamhaus.org/drop/drop.txt',
                'type': 'feed',
                'active': True,
                'description': 'Spamhaus DROP list',
                'api_key_required': False
            },
            'spamhaus_edrop': {
                'url': 'https://www.spamhaus.org/drop/edrop.txt',
                'type': 'feed',
                'active': True,
                'description': 'Spamhaus Extended DROP list',
                'api_key_required': False
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/IPv4/',
                'type': 'api',
                'active': True,
                'description': 'AlienVault OTX',
                'api_key_required': False
            }
        }
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for IP intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create IP reputation table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reputation_score INTEGER DEFAULT 50,
            threat_level TEXT DEFAULT 'unknown',
            is_blacklisted BOOLEAN DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detection_count INTEGER DEFAULT 1,
            country_code TEXT,
            isp TEXT,
            usage_type TEXT,
            abuse_confidence INTEGER DEFAULT 0,
            tags TEXT,
            sources TEXT,
            raw_data TEXT
        )
        ''')
        
        # Create IP threat feeds table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT UNIQUE,
            feed_url TEXT,
            last_updated TIMESTAMP,
            record_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create IP check history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_check_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation_score INTEGER,
            threat_level TEXT,
            sources_checked TEXT
        )
        ''')
        
        # Create IP patterns table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_range TEXT,
            category TEXT,
            risk_score INTEGER DEFAULT 50,
            description TEXT,
            source TEXT
        )
        ''')
        
        # Insert default threat feeds
        self.insert_default_feeds(cursor)
        
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ IP Intelligence Database initialized")
    
    def insert_default_feeds(self, cursor):
        """Insert default IP threat feeds"""
        feeds = [
            ('FireHOL Level 1', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 1),
            ('Spamhaus DROP', 'https://www.spamhaus.org/drop/drop.txt', 1),
            ('Spamhaus EDROP', 'https://www.spamhaus.org/drop/edrop.txt', 1),
            ('ThreatFox IPs', 'https://threatfox.abuse.ch/export/json/ip/', 1),
        ]
        
        for feed_name, feed_url, is_active in feeds:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO ip_threat_feeds (feed_name, feed_url, is_active)
                VALUES (?, ?, ?)
                ''', (feed_name, feed_url, is_active))
            except:
                pass
    
    def check_ip_reputation(self, ip_address: str, use_api: bool = False) -> Dict:
        """Check IP reputation from multiple sources"""
        result = {
            'ip': ip_address,
            'score': 50,
            'threat_level': 'medium',
            'is_blacklisted': False,
            'sources_checked': [],
            'details': {},
            'last_checked': datetime.now().isoformat()
        }
        
        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Skip private/local IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                result['threat_level'] = 'safe'
                result['score'] = 10
                result['details']['type'] = 'private_ip'
                return result
            
            # Check reserved IPs
            if ip_obj.is_reserved:
                result['threat_level'] = 'suspicious'
                result['score'] = 40
                result['details']['type'] = 'reserved_ip'
        
        except ValueError:
            result['threat_level'] = 'invalid'
            result['score'] = 100
            result['details']['error'] = 'Invalid IP address'
            return result
        
        # Check database first
        db_result = self.check_ip_in_database(ip_address)
        if db_result['found']:
            result.update(db_result['data'])
            result['sources_checked'].append('local_database')
        
        # Check blocklists (free sources)
        blocklist_results = self.check_ip_blocklists(ip_address)
        if blocklist_results['is_blacklisted']:
            result['is_blacklisted'] = True
            result['score'] = max(result['score'], 80)
            result['threat_level'] = 'high'
            result['sources_checked'].extend(blocklist_results['sources'])
            result['details']['blocklists'] = blocklist_results['lists']
        
        # Check abuse.ch ThreatFox
        threatfox_result = self.check_threatfox(ip_address)
        if threatfox_result['found']:
            result['score'] = max(result['score'], threatfox_result['score'])
            result['sources_checked'].append('threatfox')
            result['details']['threatfox'] = threatfox_result['data']
        
        # Check AlienVault OTX (free API)
        otx_result = self.check_alienvault_otx(ip_address)
        if otx_result['found']:
            result['score'] = max(result['score'], otx_result['score'])
            result['sources_checked'].append('alienvault_otx')
            result['details']['alienvault'] = otx_result['data']
        
        # If using APIs (requires API keys)
        if use_api:
            # Note: These require API keys to be configured
            abuseipdb_result = self.check_abuseipdb(ip_address)
            if abuseipdb_result['found']:
                result['score'] = max(result['score'], abuseipdb_result['score'])
                result['sources_checked'].append('abuseipdb')
                result['details']['abuseipdb'] = abuseipdb_result['data']
        
        # Determine final threat level based on score
        if result['score'] >= 80:
            result['threat_level'] = 'high'
        elif result['score'] >= 60:
            result['threat_level'] = 'medium'
        elif result['score'] >= 30:
            result['threat_level'] = 'low'
        else:
            result['threat_level'] = 'safe'
        
        # Update database with results
        self.update_ip_in_database(ip_address, result)
        
        return result
    
    def check_ip_in_database(self, ip_address: str) -> Dict:
        """Check if IP exists in local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT ip_address, reputation_score, threat_level, is_blacklisted, 
               last_seen, detection_count, tags, sources
        FROM ip_reputation 
        WHERE ip_address = ?
        ''', (ip_address,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'found': True,
                'data': {
                    'ip': row[0],
                    'score': row[1],
                    'threat_level': row[2],
                    'is_blacklisted': bool(row[3]),
                    'last_seen': row[4],
                    'detection_count': row[5],
                    'tags': row[6],
                    'sources': row[7]
                }
            }
        
        return {'found': False, 'data': {}}
    
    def check_ip_blocklists(self, ip_address: str) -> Dict:
        """Check IP against multiple blocklists"""
        result = {
            'is_blacklisted': False,
            'sources': [],
            'lists': []
        }
        
        # Common blocklists to check (these are public and don't require API keys)
        blocklists = [
            ('spamhaus_drop', self.check_spamhaus_drop),
            ('spamhaus_edrop', self.check_spamhaus_edrop),
            ('firehol', self.check_firehol),
        ]
        
        for name, check_func in blocklists:
            try:
                is_listed = check_func(ip_address)
                if is_listed:
                    result['is_blacklisted'] = True
                    result['sources'].append(name)
                    result['lists'].append(name)
            except Exception as e:
                # Silently continue if a check fails
                continue
        
        return result
    
    def check_spamhaus_drop(self, ip_address: str) -> bool:
        """Check if IP is in Spamhaus DROP list"""
        try:
            # Note: In production, you'd want to cache this list
            response = requests.get(self.ip_sources['spamhaus_drop']['url'], timeout=10)
            if response.status_code == 200:
                return ip_address in response.text
        except:
            pass
        return False
    
    def check_spamhaus_edrop(self, ip_address: str) -> bool:
        """Check if IP is in Spamhaus EDROP list"""
        try:
            response = requests.get(self.ip_sources['spamhaus_edrop']['url'], timeout=10)
            if response.status_code == 200:
                return ip_address in response.text
        except:
            pass
        return False
    
    def check_firehol(self, ip_address: str) -> bool:
        """Check if IP is in FireHOL blocklist"""
        try:
            response = requests.get(self.ip_sources['firehol']['url'], timeout=10)
            if response.status_code == 200:
                # Check if IP is in any of the CIDR ranges
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            network = ipaddress.ip_network(line)
                            if ipaddress.ip_address(ip_address) in network:
                                return True
                        except:
                            continue
        except:
            pass
        return False
    
    def check_threatfox(self, ip_address: str) -> Dict:
        """Check IP against Abuse.ch ThreatFox"""
        result = {'found': False, 'score': 0, 'data': {}}
        
        try:
            # Try to get ThreatFox data (this endpoint might need adjustment)
            url = f"https://threatfox-api.abuse.ch/api/v1/"
            data = {
                "query": "search_ioc",
                "search_term": ip_address
            }
            
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    result['found'] = True
                    result['score'] = 80  # High risk if in ThreatFox
                    result['data'] = data['data'][0] if data['data'] else {}
        except:
            pass
        
        return result
    
    def check_alienvault_otx(self, ip_address: str) -> Dict:
        """Check IP against AlienVault OTX"""
        result = {'found': False, 'score': 0, 'data': {}}
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('pulse_info', {}).get('count', 0) > 0:
                    result['found'] = True
                    pulse_count = data['pulse_info']['count']
                    # Score based on number of pulses
                    result['score'] = min(30 + (pulse_count * 10), 90)
                    result['data'] = {
                        'pulse_count': pulse_count,
                        'reputation': data.get('reputation', 0),
                        'country_name': data.get('country_name', 'Unknown')
                    }
        except:
            pass
        
        return result
    
    def check_abuseipdb(self, ip_address: str) -> Dict:
        """Check IP against AbuseIPDB (requires API key)"""
        result = {'found': False, 'score': 0, 'data': {}}
        
        # This would require an API key
        # You can add your AbuseIPDB API key here
        api_key = ""  # Add your API key here
        
        if not api_key:
            return result
        
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    result['found'] = True
                    result['score'] = data['data'].get('abuseConfidenceScore', 0)
                    result['data'] = data['data']
        except:
            pass
        
        return result
    
    def update_ip_in_database(self, ip_address: str, reputation_data: Dict):
        """Update or insert IP reputation in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if IP exists
        cursor.execute('SELECT id, detection_count FROM ip_reputation WHERE ip_address = ?', (ip_address,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing record
            ip_id, count = existing
            cursor.execute('''
            UPDATE ip_reputation 
            SET reputation_score = ?,
                threat_level = ?,
                is_blacklisted = ?,
                last_seen = CURRENT_TIMESTAMP,
                detection_count = detection_count + 1,
                sources = ?
            WHERE id = ?
            ''', (
                reputation_data['score'],
                reputation_data['threat_level'],
                1 if reputation_data.get('is_blacklisted') else 0,
                ','.join(reputation_data.get('sources_checked', [])),
                ip_id
            ))
        else:
            # Insert new record
            cursor.execute('''
            INSERT INTO ip_reputation 
            (ip_address, reputation_score, threat_level, is_blacklisted, sources)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                ip_address,
                reputation_data['score'],
                reputation_data['threat_level'],
                1 if reputation_data.get('is_blacklisted') else 0,
                ','.join(reputation_data.get('sources_checked', []))
            ))
        
        # Add to check history
        cursor.execute('''
        INSERT INTO ip_check_history 
        (ip_address, reputation_score, threat_level, sources_checked)
        VALUES (?, ?, ?, ?)
        ''', (
            ip_address,
            reputation_data['score'],
            reputation_data['threat_level'],
            ','.join(reputation_data.get('sources_checked', []))
        ))
        
        conn.commit()
        conn.close()
    
    def update_threat_feeds(self):
        """Update IP threat feeds from sources"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}🔄 Updating IP threat feeds...")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        total_ips = 0
        
        # Update FireHOL
        try:
            response = requests.get(self.ip_sources['firehol']['url'], timeout=30)
            if response.status_code == 200:
                ips_added = 0
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            # Store IP range pattern
                            cursor.execute('''
                            INSERT OR IGNORE INTO ip_patterns (ip_range, category, risk_score, description, source)
                            VALUES (?, ?, ?, ?, ?)
                            ''', (line, 'firehol_blocklist', 80, 'FireHOL Level 1 blocklist', 'firehol'))
                            ips_added += 1
                        except:
                            continue
                
                cursor.execute('''
                UPDATE ip_threat_feeds 
                SET last_updated = CURRENT_TIMESTAMP, record_count = ?
                WHERE feed_name = 'FireHOL Level 1'
                ''', (ips_added,))
                
                total_ips += ips_added
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}  FireHOL: Added {ips_added} IP ranges")
        except Exception as e:
            print(f"{Fore.RED if COLORS_ENABLED else ''}  FireHOL update failed: {e}")
        
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Total IP patterns updated: {total_ips}")
        return total_ips