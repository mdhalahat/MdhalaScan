"""
MdhalaScan v1.0 - File Malware Scanner Module
Static and dynamic analysis of suspicious files with free threat intelligence
"""

import os
import re
import io
import zipfile
import hashlib
import struct
import math
import json
import sqlite3
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, BinaryIO
from pathlib import Path
import mimetypes

# Import from utils
from utils import Fore, COLORS_ENABLED, Style, ProgressBar

# Try to import file analysis libraries
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

# For Office documents
try:
    from oletools.olevba import VBA_Parser, VBA_Scanner
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

# For PDF analysis
try:
    from pdfminer.high_level import extract_text
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False

import requests
from urllib.parse import urlparse

class FileIntelligenceDB:
    """Database for file hash intelligence and signatures"""
    
    def __init__(self, db_path: str = "file_intel.db"):
        self.db_path = db_path
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
        ]
        
        # Free threat intelligence feeds
        self.threat_feeds = {
            'malwarebazaar': {
                'url': 'https://bazaar.abuse.ch/export/txt/md5/recent/',
                'format': 'text',
                'active': True,
                'description': 'MalwareBazaar recent MD5 hashes',
                'free': True
            },
            'threatfox': {
                'url': 'https://threatfox.abuse.ch/export/csv/full/',
                'format': 'csv',
                'active': True,
                'description': 'ThreatFox IOCs',
                'free': True
            },
            'yara_rules': {
                'url': 'https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip',
                'format': 'zip',
                'active': True,
                'description': 'Community YARA rules',
                'free': True
            }
        }
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for file intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create known malware hashes table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_md5 TEXT UNIQUE,
            hash_sha1 TEXT,
            hash_sha256 TEXT,
            file_type TEXT,
            threat_name TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            source TEXT,
            detection_count INTEGER DEFAULT 1,
            risk_score INTEGER DEFAULT 80
        )
        ''')
        
        # Create YARA rules table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS yara_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT UNIQUE,
            rule_content TEXT,
            category TEXT,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create file signatures table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            magic_bytes TEXT,
            file_extension TEXT,
            file_type TEXT,
            description TEXT,
            risk_level TEXT DEFAULT 'low'
        )
        ''')
        
        # Create analysis history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            file_hash TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            risk_score INTEGER,
            threat_name TEXT,
            analysis_type TEXT,
            findings TEXT
        )
        ''')
        
        # Create threat feeds table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT UNIQUE,
            feed_url TEXT,
            last_fetched TIMESTAMP,
            record_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Insert default threat feeds
        self.insert_default_feeds(cursor)
        
        # Insert default file signatures
        self.insert_default_signatures(cursor)
        
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ File Intelligence Database initialized")
    
    def insert_default_feeds(self, cursor):
        """Insert default threat intelligence feeds"""
        for feed_name, feed_info in self.threat_feeds.items():
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO threat_feeds 
                (feed_name, feed_url, is_active)
                VALUES (?, ?, ?)
                ''', (feed_name, feed_info['url'], feed_info['active']))
            except Exception as e:
                print(f"Error inserting feed {feed_name}: {e}")
    
    def insert_default_signatures(self, cursor):
        """Insert default file signatures (magic bytes)"""
        signatures = [
            # Executables
            ('4D5A', 'exe', 'Windows EXE', 'DOS executable header', 'high'),
            ('7F454C46', 'elf', 'Linux ELF', 'Executable and Linkable Format', 'high'),
            ('CAFEBABE', 'class', 'Java class', 'Java bytecode', 'medium'),
            
            # Office Documents
            ('D0CF11E0A1B11AE1', 'doc', 'Microsoft Word', 'Compound File Binary Format', 'medium'),
            ('504B0304', 'docx', 'Office Open XML', 'ZIP archive (DOCX, XLSX, PPTX)', 'medium'),
            
            # Archives
            ('504B0304', 'zip', 'ZIP archive', 'Standard ZIP file', 'low'),
            ('52617221', 'rar', 'RAR archive', 'RAR archive version 1.5+', 'low'),
            ('377ABCAF271C', '7z', '7-Zip archive', '7z archive', 'low'),
            
            # PDF
            ('25504446', 'pdf', 'PDF document', 'Portable Document Format', 'medium'),
            
            # Scripts
            ('2321', 'sh', 'Shell script', 'Shebang (#!)', 'medium'),
            ('3C3F706870', 'php', 'PHP script', 'PHP opening tag', 'medium'),
            
            # Images (generally safe but can be used for stego)
            ('FFD8FF', 'jpg', 'JPEG image', 'JPEG File Interchange Format', 'low'),
            ('89504E47', 'png', 'PNG image', 'Portable Network Graphics', 'low'),
        ]
        
        for magic_bytes, extension, file_type, description, risk_level in signatures:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO file_signatures 
                (magic_bytes, file_extension, file_type, description, risk_level)
                VALUES (?, ?, ?, ?, ?)
                ''', (magic_bytes, extension, file_type, description, risk_level))
            except:
                pass
    
    def update_threat_feeds(self) -> Dict:
        """Update threat intelligence feeds"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}🔄 Updating File Threat Intelligence Feeds")
        
        results = {}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for feed_name, feed_info in self.threat_feeds.items():
            if not feed_info['active']:
                continue
            
            print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}[{feed_name.upper()}]")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Fetching from: {feed_info['description']}")
            
            try:
                headers = {'User-Agent': self.user_agents[0]}
                response = requests.get(feed_info['url'], headers=headers, timeout=30)
                
                if response.status_code != 200:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed: HTTP {response.status_code}")
                    continue
                
                added_count = 0
                
                if feed_name == 'malwarebazaar':
                    # Parse MalwareBazaar MD5 hashes
                    for line in response.text.split('\n'):
                        if line.strip() and not line.startswith('#'):
                            hash_md5 = line.strip().lower()
                            if len(hash_md5) == 32:  # Valid MD5
                                cursor.execute('''
                                INSERT OR IGNORE INTO malware_hashes 
                                (hash_md5, source, first_seen)
                                VALUES (?, ?, CURRENT_TIMESTAMP)
                                ''', (hash_md5, 'malwarebazaar'))
                                added_count += 1
                
                elif feed_name == 'threatfox':
                    # Parse ThreatFox CSV
                    lines = response.text.split('\n')
                    for line in lines[1:]:  # Skip header
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 8:
                                # Extract hashes from IOCs
                                ioc = parts[2].strip('"')
                                if ioc.startswith('md5:'):
                                    hash_md5 = ioc[4:].lower()
                                    if len(hash_md5) == 32:
                                        cursor.execute('''
                                        INSERT OR IGNORE INTO malware_hashes 
                                        (hash_md5, threat_name, source, first_seen)
                                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                                        ''', (hash_md5, parts[5].strip('"'), 'threatfox'))
                                        added_count += 1
                
                elif feed_name == 'yara_rules':
                    # Download and extract YARA rules
                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}YARA rules update requires manual extraction")
                    # This would extract YARA rules from the ZIP
                    # For simplicity, we'll just note it's available
                    added_count = -1  # Special value for manual extraction
                
                # Update feed record
                cursor.execute('''
                UPDATE threat_feeds 
                SET last_fetched = CURRENT_TIMESTAMP,
                    record_count = record_count + ?
                WHERE feed_name = ?
                ''', (added_count if added_count > 0 else 0, feed_name))
                
                if added_count > 0:
                    print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Added {added_count} records")
                elif added_count == -1:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ Manual extraction required for YARA rules")
                else:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ No new records found")
                
                results[feed_name] = added_count
                
            except Exception as e:
                print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Error: {str(e)}")
                results[feed_name] = 0
        
        conn.commit()
        conn.close()
        
        print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ Threat feeds update completed")
        return results
    
    def check_hash_reputation(self, file_hash: str) -> Tuple[bool, Dict]:
        """Check file hash against known malware databases"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Try different hash types
        hash_length = len(file_hash)
        
        if hash_length == 32:  # MD5
            cursor.execute('''
            SELECT hash_md5, threat_name, first_seen, source, risk_score
            FROM malware_hashes 
            WHERE hash_md5 = ?
            ''', (file_hash.lower(),))
        elif hash_length == 40:  # SHA1
            cursor.execute('''
            SELECT hash_md5, threat_name, first_seen, source, risk_score
            FROM malware_hashes 
            WHERE hash_sha1 = ?
            ''', (file_hash.lower(),))
        elif hash_length == 64:  # SHA256
            cursor.execute('''
            SELECT hash_md5, threat_name, first_seen, source, risk_score
            FROM malware_hashes 
            WHERE hash_sha256 = ?
            ''', (file_hash.lower(),))
        else:
            conn.close()
            return False, {}
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return True, {
                'hash': result[0],
                'threat_name': result[1],
                'first_seen': result[2],
                'source': result[3],
                'risk_score': result[4]
            }
        
        return False, {}
    
    def add_hash_to_database(self, file_hash: str, threat_name: str = "Unknown", 
                           source: str = "manual", risk_score: int = 70):
        """Add a hash to the malware database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        hash_length = len(file_hash)
        hash_type = 'md5' if hash_length == 32 else 'sha1' if hash_length == 40 else 'sha256'
        
        try:
            if hash_type == 'md5':
                cursor.execute('''
                INSERT OR REPLACE INTO malware_hashes 
                (hash_md5, threat_name, source, risk_score, last_seen, detection_count)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 
                    COALESCE((SELECT detection_count + 1 FROM malware_hashes WHERE hash_md5 = ?), 1))
                ''', (file_hash.lower(), threat_name, source, risk_score, file_hash.lower()))
            elif hash_type == 'sha1':
                cursor.execute('''
                INSERT OR REPLACE INTO malware_hashes 
                (hash_sha1, threat_name, source, risk_score, last_seen, detection_count)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP,
                    COALESCE((SELECT detection_count + 1 FROM malware_hashes WHERE hash_sha1 = ?), 1))
                ''', (file_hash.lower(), threat_name, source, risk_score, file_hash.lower()))
            else:  # sha256
                cursor.execute('''
                INSERT OR REPLACE INTO malware_hashes 
                (hash_sha256, threat_name, source, risk_score, last_seen, detection_count)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP,
                    COALESCE((SELECT detection_count + 1 FROM malware_hashes WHERE hash_sha256 = ?), 1))
                ''', (file_hash.lower(), threat_name, source, risk_score, file_hash.lower()))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding hash: {e}")
            return False
        finally:
            conn.close()
    
    def get_database_statistics(self) -> Dict:
        """Get file intelligence database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Get total malware hashes
        cursor.execute('SELECT COUNT(*) FROM malware_hashes')
        stats['total_hashes'] = cursor.fetchone()[0]
        
        # Get hashes by source
        cursor.execute('''
        SELECT source, COUNT(*) as count
        FROM malware_hashes
        GROUP BY source
        ORDER BY count DESC
        ''')
        stats['hashes_by_source'] = dict(cursor.fetchall())
        
        # Get recent analyses
        cursor.execute('''
        SELECT COUNT(*) as total_scans,
               SUM(CASE WHEN risk_score > 60 THEN 1 ELSE 0 END) as malicious_detections,
               SUM(CASE WHEN risk_score > 30 AND risk_score <= 60 THEN 1 ELSE 0 END) as suspicious_detections,
               MAX(analyzed_at) as last_scan
        FROM analysis_history
        ''')
        row = cursor.fetchone()
        stats['analysis_summary'] = {
            'total_scans': row[0] or 0,
            'malicious_detections': row[1] or 0,
            'suspicious_detections': row[2] or 0,
            'last_scan': row[3]
        }
        
        # Get threat feed status
        cursor.execute('''
        SELECT feed_name, last_fetched, record_count, is_active
        FROM threat_feeds
        ''')
        stats['feed_status'] = []
        for row in cursor.fetchall():
            stats['feed_status'].append({
                'feed_name': row[0],
                'last_fetched': row[1],
                'record_count': row[2],
                'is_active': bool(row[3])
            })
        
        conn.close()
        return stats

class FileScanner:
    """Main file scanner class with multiple analysis techniques"""
    
    def __init__(self, file_intel: Optional[FileIntelligenceDB] = None):
        self.file_intel = file_intel or FileIntelligenceDB()
        self.progress_bar = ProgressBar()
        
        # YARA rules compilation
        self.yara_rules = None
        self.init_yara_rules()
    
    def init_yara_rules(self):
        """Initialize YARA rules if available"""
        if not YARA_AVAILABLE:
            return
        
        try:
            # Basic YARA rules for common malware patterns
            yara_rules_source = '''
            rule Suspicious_JavaScript {
                strings:
                    $eval = "eval("
                    $document_write = "document.write"
                    $fromcharcode = "fromCharCode"
                    $unescape = "unescape("
                condition:
                    any of them
            }
            
            rule PowerShell_Suspicious {
                strings:
                    $bypass = "Bypass"
                    $encoded = "-EncodedCommand"
                    $hidden = "-WindowStyle Hidden"
                    $noprofile = "-NoProfile"
                condition:
                    any of them
            }
            
            rule Office_Macro {
                strings:
                    $autopen = "AutoOpen"
                    $autoclose = "AutoClose"
                    $autoexec = "AutoExec"
                    $shell = "Shell("
                    $wscript = "WScript.Shell"
                condition:
                    2 of them
            }
            
            rule PDF_JavaScript {
                strings:
                    $js = "/JavaScript"
                    $aa = "/AA"
                    $openaction = "/OpenAction"
                    $js_ref = "/JS"
                condition:
                    2 of them
            }
            '''
            
            self.yara_rules = yara.compile(source=yara_rules_source)
        except Exception as e:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ YARA rules compilation failed: {e}")
            self.yara_rules = None
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        data_len = len(data)
        
        # Count frequency of each byte value
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hash types for a file"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Calculate standard hashes
            hashes['md5'] = hashlib.md5(file_data).hexdigest()
            hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
            
            # Calculate SSDEEP fuzzy hash if available
            if SSDEEP_AVAILABLE:
                try:
                    hashes['ssdeep'] = ssdeep.hash(file_data)
                except:
                    hashes['ssdeep'] = "N/A"
            else:
                hashes['ssdeep'] = "N/A"
            
            # File size
            hashes['size'] = str(len(file_data))
            
        except Exception as e:
            print(f"Error calculating hashes: {e}")
        
        return hashes
    
    def detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Detect file type using multiple methods"""
        result = {
            'magic_bytes': '',
            'extension': '',
            'mime_type': '',
            'detected_type': 'Unknown'
        }
        
        try:
            # Get file extension
            _, file_extension = os.path.splitext(file_path)
            result['extension'] = file_extension.lower().lstrip('.')
            
            # Read magic bytes
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(20)  # Read first 20 bytes
            
            result['magic_bytes'] = magic_bytes.hex().upper()
            
            # Try python-magic if available
            if MAGIC_AVAILABLE:
                try:
                    mime = magic.from_file(file_path, mime=True)
                    result['mime_type'] = mime
                except:
                    pass
            
            # Check against known signatures
            conn = sqlite3.connect(self.file_intel.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT file_type, description, risk_level
            FROM file_signatures
            WHERE ? LIKE magic_bytes || '%'
            ''', (result['magic_bytes'],))
            
            sig_result = cursor.fetchone()
            if sig_result:
                result['detected_type'] = sig_result[0]
                result['signature_description'] = sig_result[1]
                result['signature_risk'] = sig_result[2]
            
            conn.close()
            
            # Fallback to mimetypes
            if result['detected_type'] == 'Unknown':
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type:
                    result['mime_type'] = mime_type
                    result['detected_type'] = mime_type.split('/')[0].title()
        
        except Exception as e:
            print(f"Error detecting file type: {e}")
        
        return result
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary file"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []
            
            # Add last string if any
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
        
        except Exception as e:
            print(f"Error extracting strings: {e}")
        
        return strings
    
    def analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze Portable Executable (PE) files"""
        result = {
            'is_pe': False,
            'sections': [],
            'imports': [],
            'suspicious_indicators': []
        }
        
        if not PEFILE_AVAILABLE:
            return result
        
        try:
            pe = pefile.PE(file_path)
            result['is_pe'] = True
            
            # Get section information
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy(),
                    'characteristics': section.Characteristics
                }
                result['sections'].append(section_info)
                
                # Check for suspicious section characteristics
                if section_info['entropy'] > 7.0:
                    result['suspicious_indicators'].append(f"High entropy section ({section_info['name']}: {section_info['entropy']:.2f})")
            
            # Get imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports = [imp.name.decode('utf-8', errors='ignore') for imp in entry.imports if imp.name]
                    result['imports'].append({'dll': dll_name, 'functions': imports})
                    
                    # Check for suspicious imports
                    suspicious_dlls = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll']
                    suspicious_funcs = ['CreateProcess', 'ShellExecute', 'WinExec', 'VirtualAlloc', 
                                      'CreateRemoteThread', 'WriteProcessMemory', 'URLDownloadToFile']
                    
                    if dll_name.lower() in suspicious_dlls:
                        for func in imports:
                            if func in suspicious_funcs:
                                result['suspicious_indicators'].append(f"Suspicious import: {dll_name}!{func}")
            
            # Check for packed executable indicators
            if len(result['sections']) > 0:
                text_section = next((s for s in result['sections'] if s['name'].lower() == '.text'), None)
                if text_section and text_section['raw_size'] == 0:
                    result['suspicious_indicators'].append("Possible packed executable (.text section raw size = 0)")
            
            pe.close()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_pdf_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze PDF files for malicious content"""
        result = {
            'is_pdf': False,
            'javascript_found': False,
            'auto_action_found': False,
            'suspicious_indicators': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Check for PDF magic bytes
            if data[:4] == b'%PDF':
                result['is_pdf'] = True
                
                # Look for JavaScript
                if b'/JavaScript' in data or b'/JS' in data:
                    result['javascript_found'] = True
                    result['suspicious_indicators'].append("JavaScript found in PDF")
                
                # Look for auto actions
                if b'/AA' in data or b'/OpenAction' in data:
                    result['auto_action_found'] = True
                    result['suspicious_indicators'].append("Auto-action found in PDF")
                
                # Look for embedded files
                if b'/EmbeddedFile' in data or b'/EmbeddedFiles' in data:
                    result['suspicious_indicators'].append("Embedded files found in PDF")
                
                # Extract text if PDFMiner is available
                if PDFMINER_AVAILABLE:
                    try:
                        text = extract_text(file_path)
                        # Look for suspicious URLs
                        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)
                        if urls:
                            result['suspicious_indicators'].append(f"URLs found in PDF: {len(urls)}")
                    except:
                        pass
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_office_document(self, file_path: str) -> Dict[str, Any]:
        """Analyze Office documents for macros"""
        result = {
            'is_office': False,
            'has_macros': False,
            'suspicious_macros': [],
            'suspicious_indicators': []
        }
        
        if not OLETOOLS_AVAILABLE:
            return result
        
        try:
            vbaparser = VBA_Parser(file_path)
            
            if vbaparser.detect_vba_macros():
                result['is_office'] = True
                result['has_macros'] = True
                
                # Extract macro code
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    # Check for suspicious keywords
                    suspicious_keywords = [
                        'Shell', 'CreateObject', 'WScript.Shell', 'ActiveXObject',
                        'DownloadFile', 'SaveToFile', 'Run', 'Execute',
                        'AutoOpen', 'AutoClose', 'AutoExec', 'Document_Open'
                    ]
                    
                    for keyword in suspicious_keywords:
                        if keyword in vba_code:
                            if keyword not in result['suspicious_macros']:
                                result['suspicious_macros'].append(keyword)
                                result['suspicious_indicators'].append(f"Suspicious macro keyword: {keyword}")
                
                vbaparser.close()
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_archive(self, file_path: str) -> Dict[str, Any]:
        """Analyze archive files (ZIP, RAR, etc.)"""
        result = {
            'is_archive': False,
            'file_count': 0,
            'suspicious_files': [],
            'suspicious_indicators': []
        }
        
        try:
            # Check for ZIP
            if zipfile.is_zipfile(file_path):
                result['is_archive'] = True
                
                with zipfile.ZipFile(file_path, 'r') as zipf:
                    result['file_count'] = len(zipf.namelist())
                    
                    # Check each file in archive
                    for filename in zipf.namelist():
                        # Check for suspicious file extensions
                        suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
                        file_ext = os.path.splitext(filename)[1].lower()
                        
                        if file_ext in suspicious_extensions:
                            result['suspicious_files'].append(filename)
                            result['suspicious_indicators'].append(f"Suspicious file in archive: {filename}")
                        
                        # Check for double extensions
                        if len(filename.split('.')) > 2:
                            base_ext = filename.split('.')[-2].lower()
                            final_ext = filename.split('.')[-1].lower()
                            if base_ext in ['exe', 'bat', 'cmd', 'ps1'] and final_ext in ['txt', 'pdf', 'doc']:
                                result['suspicious_indicators'].append(f"Double extension detected: {filename}")
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_external_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against external free APIs"""
        result = {
            'malwarebazaar': {'found': False, 'details': {}},
            'threatfox': {'found': False, 'details': {}}
        }
        
        try:
            # Check MalwareBazaar API
            mb_url = f"https://mb-api.abuse.ch/api/v1/"
            mb_data = {
                'query': 'get_info',
                'hash': file_hash
            }
            
            mb_response = requests.post(mb_url, data=mb_data, timeout=10)
            if mb_response.status_code == 200:
                mb_json = mb_response.json()
                if mb_json.get('query_status') == 'ok':
                    result['malwarebazaar']['found'] = True
                    result['malwarebazaar']['details'] = mb_json.get('data', [{}])[0]
            
            # Check ThreatFox API (for IOCs)
            tf_url = "https://threatfox.abuse.ch/api/v1/"
            tf_data = {
                'query': 'search_hash',
                'hash': file_hash
            }
            
            tf_response = requests.post(tf_url, json=tf_data, timeout=10)
            if tf_response.status_code == 200:
                tf_json = tf_response.json()
                if tf_json.get('query_status') == 'ok':
                    result['threatfox']['found'] = True
                    result['threatfox']['details'] = tf_json.get('data', {})
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def apply_yara_rules(self, file_path: str) -> List[Dict]:
        """Apply YARA rules to file"""
        matches = []
        
        if not self.yara_rules:
            return matches
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            yara_matches = self.yara_rules.match(data=file_data)
            
            for match in yara_matches:
                matches.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                })
        
        except Exception as e:
            print(f"YARA scan error: {e}")
        
        return matches
    
    def scan_file(self, file_path: str, deep_analysis: bool = True) -> Dict[str, Any]:
        """Main file scanning function"""
        if not os.path.exists(file_path):
            return {'error': f"File not found: {file_path}"}
        
        results = {
            'filename': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'scan_time': datetime.now().isoformat(),
            'risk_score': 0,
            'findings': [],
            'recommendation': 'File appears safe',
            'threat_name': 'Unknown',
            'hashes': {},
            'file_type': {},
            'analysis_results': {},
            'yara_matches': [],
            'external_reputation': {},
            'hash_match': False
        }
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🛡️  FILE MALWARE ANALYSIS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}File: {file_path}")
        
        risk_points = 0
        max_points = 100
        
        # Step 1: Calculate file hashes
        print(f"\n{self.progress_bar.create_scan_progress(1, 8, 'Calculating hashes...')}")
        results['hashes'] = self.calculate_file_hashes(file_path)
        
        # Step 2: Check hash against intelligence database
        print(f"\n{self.progress_bar.create_scan_progress(2, 8, 'Checking hash reputation...')}")
        if self.file_intel:
            hash_match, intel_info = self.file_intel.check_hash_reputation(results['hashes']['md5'])
            if hash_match:
                results['hash_match'] = True
                results['threat_name'] = intel_info.get('threat_name', 'Known malware')
                results['intel_info'] = intel_info
                risk_points += 50
                results['findings'].append(f"❌ Hash matches known malware: {intel_info.get('threat_name')}")
        
        # Step 3: Detect file type
        print(f"\n{self.progress_bar.create_scan_progress(3, 8, 'Analyzing file type...')}")
        results['file_type'] = self.detect_file_type(file_path)
        
        # Check for mismatched file type/extension
        if results['file_type']['detected_type'] != 'Unknown':
            ext = results['file_type']['extension']
            detected = results['file_type']['detected_type'].lower()
            
            suspicious_extensions = {
                'exe': 'executable',
                'dll': 'library',
                'bat': 'batch',
                'cmd': 'command',
                'ps1': 'powershell',
                'vbs': 'vbscript',
                'js': 'javascript',
                'jar': 'java'
            }
            
            if ext in suspicious_extensions and suspicious_extensions[ext] not in detected:
                risk_points += 15
                results['findings'].append(f"⚠️ File extension mismatch: .{ext} but detected as {detected}")
        
        # Step 4: Calculate entropy
        print(f"\n{self.progress_bar.create_scan_progress(4, 8, 'Calculating entropy...')}")
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        entropy = self.calculate_entropy(file_data)
        results['analysis_results']['entropy'] = entropy
        
        if entropy > 7.5:
            risk_points += 20
            results['findings'].append(f"⚠️ High entropy detected: {entropy:.2f} (possible encryption/packing)")
        elif entropy > 6.5:
            risk_points += 10
            results['findings'].append(f"⚠️ Moderate entropy: {entropy:.2f}")
        
        # Step 5: Apply YARA rules
        print(f"\n{self.progress_bar.create_scan_progress(5, 8, 'Running YARA rules...')}")
        yara_matches = self.apply_yara_rules(file_path)
        results['yara_matches'] = yara_matches
        
        for match in yara_matches:
            risk_points += 15
            results['findings'].append(f"⚠️ YARA rule matched: {match['rule']}")
        
        # Step 6: Type-specific analysis
        print(f"\n{self.progress_bar.create_scan_progress(6, 8, 'Performing deep analysis...')}")
        if deep_analysis:
            # PE file analysis
            if results['file_type']['detected_type'] in ['Windows EXE', 'Linux ELF']:
                pe_analysis = self.analyze_pe_file(file_path)
                results['analysis_results']['pe_analysis'] = pe_analysis
                
                for indicator in pe_analysis.get('suspicious_indicators', []):
                    risk_points += 10
                    results['findings'].append(f"⚠️ {indicator}")
            
            # PDF analysis
            elif results['file_type']['detected_type'] == 'PDF':
                pdf_analysis = self.analyze_pdf_file(file_path)
                results['analysis_results']['pdf_analysis'] = pdf_analysis
                
                for indicator in pdf_analysis.get('suspicious_indicators', []):
                    risk_points += 10
                    results['findings'].append(f"⚠️ {indicator}")
            
            # Office document analysis
            elif results['file_type']['detected_type'] in ['Microsoft Word', 'Office Open XML']:
                office_analysis = self.analyze_office_document(file_path)
                results['analysis_results']['office_analysis'] = office_analysis
                
                if office_analysis.get('has_macros'):
                    risk_points += 25
                    results['findings'].append("⚠️ Macros found in Office document")
                
                for indicator in office_analysis.get('suspicious_indicators', []):
                    risk_points += 10
                    results['findings'].append(f"⚠️ {indicator}")
            
            # Archive analysis
            elif results['file_type']['detected_type'] in ['ZIP archive', 'RAR archive', '7z archive']:
                archive_analysis = self.analyze_archive(file_path)
                results['analysis_results']['archive_analysis'] = archive_analysis
                
                for indicator in archive_analysis.get('suspicious_indicators', []):
                    risk_points += 10
                    results['findings'].append(f"⚠️ {indicator}")
        
        # Step 7: Check external reputation
        print(f"\n{self.progress_bar.create_scan_progress(7, 8, 'Checking external APIs...')}")
        ext_reputation = self.check_external_reputation(results['hashes']['md5'])
        results['external_reputation'] = ext_reputation
        
        if ext_reputation['malwarebazaar']['found']:
            risk_points += 40
            results['findings'].append("❌ File found in MalwareBazaar database")
        
        if ext_reputation['threatfox']['found']:
            risk_points += 40
            results['findings'].append("❌ File found in ThreatFox database")
        
        # Step 8: Extract strings and look for suspicious patterns
        print(f"\n{self.progress_bar.create_scan_progress(8, 8, 'Extracting strings...')}")
        strings = self.extract_strings(file_path)
        suspicious_strings = 0
        
        # Check for suspicious patterns in strings
        suspicious_patterns = [
            ('http://', 'URL'),
            ('https://', 'Secure URL'),
            ('cmd.exe', 'Command prompt'),
            ('powershell', 'PowerShell'),
            ('regsvr32', 'DLL registration'),
            ('schtasks', 'Scheduled tasks'),
            ('net user', 'User account manipulation'),
            ('format ', 'Disk formatting'),
            ('del /f', 'Force delete'),
            ('attrib +h', 'Hide files')
        ]
        
        for pattern, description in suspicious_patterns:
            for string in strings:
                if pattern in string.lower():
                    suspicious_strings += 1
                    break
        
        if suspicious_strings > 0:
            risk_points += suspicious_strings * 5
            results['findings'].append(f"⚠️ Found {suspicious_strings} suspicious string patterns")
        
        # Calculate final risk score
        results['risk_score'] = min(risk_points, max_points)
        
        # Determine recommendation
        if results['risk_score'] <= 30:
            results['recommendation'] = 'File appears safe for normal use'
        elif results['risk_score'] <= 60:
            results['recommendation'] = 'Exercise caution with this file'
        else:
            results['recommendation'] = 'HIGH RISK - Do not open this file!'
        
        # Save analysis to history
        if self.file_intel:
            conn = sqlite3.connect(self.file_intel.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO analysis_history 
            (filename, file_hash, risk_score, threat_name, analysis_type, findings)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                results['filename'],
                results['hashes']['md5'],
                results['risk_score'],
                results['threat_name'],
                'full_scan',
                json.dumps(results['findings'])
            ))
            
            conn.commit()
            conn.close()
        
        return results
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, Any]:
        """Scan all files in a directory"""
        results = {
            'directory': directory_path,
            'total_files': 0,
            'scanned_files': 0,
            'malicious_files': 0,
            'suspicious_files': 0,
            'safe_files': 0,
            'file_results': [],
            'scan_time': datetime.now().isoformat()
        }
        
        if not os.path.exists(directory_path):
            return {'error': f"Directory not found: {directory_path}"}
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📁 DIRECTORY MALWARE SCAN")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Directory: {directory_path}")
        
        # Collect all files
        all_files = []
        
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    all_files.append(os.path.join(root, file))
        else:
            all_files = [os.path.join(directory_path, f) for f in os.listdir(directory_path) 
                        if os.path.isfile(os.path.join(directory_path, f))]
        
        results['total_files'] = len(all_files)
        
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Found {len(all_files)} files to scan")
        
        # Scan each file
        for i, file_path in enumerate(all_files):
            if i % 10 == 0:  # Show progress every 10 files
                print(f"\n{self.progress_bar.create_scan_progress(i, len(all_files), f'Scanning files... ({i}/{len(all_files)})')}")
            
            try:
                file_result = self.scan_file(file_path, deep_analysis=False)  # Quick scan for directory
                results['file_results'].append(file_result)
                results['scanned_files'] += 1
                
                if file_result['risk_score'] > 60:
                    results['malicious_files'] += 1
                    print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Malicious: {os.path.basename(file_path)}")
                elif file_result['risk_score'] > 30:
                    results['suspicious_files'] += 1
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ Suspicious: {os.path.basename(file_path)}")
                else:
                    results['safe_files'] += 1
                    print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Safe: {os.path.basename(file_path)}")
            
            except Exception as e:
                print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Error scanning {file_path}: {e}")
        
        return results
    
    def quarantine_file(self, file_path: str, quarantine_dir: str = "quarantine") -> bool:
        """Move suspicious file to quarantine"""
        try:
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
            
            # Generate quarantine filename
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantined_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(quarantine_dir, quarantined_name)
            
            # Move file
            import shutil
            shutil.move(file_path, quarantine_path)
            
            # Log quarantine action
            log_file = os.path.join(quarantine_dir, "quarantine.log")
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} | {file_path} -> {quarantine_path}\n")
            
            return True
        
        except Exception as e:
            print(f"Error quarantining file: {e}")
            return False