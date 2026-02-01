#!/usr/bin/env python3
"""
MdhalaScan v1.0 - Enhanced with PDF Reports & IP Reputation
Author: MdhalaHat
Description: Phishing scanner with web scraping, IP reputation, and PDF reporting
"""

import os
import sys
import warnings
import subprocess
import re
import sqlite3  # ADD THIS IMPORT
from datetime import datetime
from urllib.parse import urlparse  # ADD THIS IMPORT

warnings.filterwarnings('ignore')

# Import all modules
from utils import Fore, COLORS_ENABLED, Style
from intelligence import PhishingIntelligenceDB
from ipscan import IPIntelligenceDB
from urlscan import URLScanner
from emailscan import EmailScanner
from pdfreport import PDFReportGenerator
from result_presenter import ResultPresenter

# Import for file scan 
from filescan import FileScanner, FileIntelligenceDB

class MdhalaScan:
    """Main class for MdhalaScan scanner"""
    
    def __init__(self):
        self.version = "1.8"
        self.author = "MdhalaHat"
        self.phishing_intel = PhishingIntelligenceDB()
        self.ip_intel = IPIntelligenceDB()
        self.file_intel = FileIntelligenceDB()  # File intelligence database
        self.pdf_reporter = PDFReportGenerator()
    
    def print_banner(self):
        """Print the main banner"""
        if COLORS_ENABLED:
            banner = f"""
{Fore.CYAN}{'█' * 60}
{Fore.CYAN}{'█' * 60}
{Fore.MAGENTA}{Style.BRIGHT}
{Fore.MAGENTA} ███╗   ███╗██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ 
{Fore.MAGENTA} ████╗ ████║██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗
{Fore.MAGENTA} ██╔████╔██║██║  ██║███████║███████║██║     ███████║
{Fore.MAGENTA} ██║╚██╔╝██║██║  ██║██╔══██║██╔══██║██║     ██╔══██║
{Fore.MAGENTA} ██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║███████╗██║  ██║
{Fore.MAGENTA} ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Fore.CYAN}{Style.BRIGHT}
{Fore.CYAN} ███████╗ ██████╗ █████╗ ███╗   ██╗
{Fore.CYAN} ██╔════╝██╔════╝██╔══██╗████╗  ██║
{Fore.CYAN} ███████╗██║     ███████║██╔██╗ ██║
{Fore.CYAN} ╚════██║██║     ██╔══██║██║╚██╗██║
{Fore.CYAN} ███████║╚██████╗██║  ██║██║ ╚████║
{Fore.CYAN} ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}{'─' * 60}
{Fore.GREEN}         URL , Email , IP , FIles Scanner
{Fore.YELLOW}{'─' * 60}
{Fore.WHITE}              by {Fore.CYAN}MdhalaHat
{Fore.YELLOW}{'─' * 60}
{Fore.WHITE}Version: {Fore.GREEN}1.8{Fore.WHITE} | {Fore.WHITE}GitHub: {Fore.CYAN}github.com/mdhalahat
{Fore.WHITE}Website: {Fore.CYAN}mdhalahat.com{Fore.WHITE} | {Fore.WHITE}Instagram: {Fore.CYAN}@mdhalahat
{Fore.WHITE}Facebook: MdhalaHat | Tiktok: @mdhala.hat
{Fore.WHITE}Linkedin: MdhalaHat
{Fore.YELLOW}{'─' * 60}
{Fore.RED}{Style.BRIGHT}⚠️  FOR EDUCATIONAL & ETHICAL USE ONLY!
{Fore.RED}Use only on websites you own or have permission to test.
{Fore.YELLOW}{'─' * 60}
{Fore.CYAN}              Made in Tunisia 🇹🇳
{Fore.YELLOW}{'─' * 60}
{Style.RESET_ALL}
            """
        else:
            banner = """
████████████████████████████████████████████████████████████
╔══════════════════════════════════════════════════════════╗
║                    M D H A L A S C A N                   ║
╠══════════════════════════════════════════════════════════╣
║            URL & Email Phishing Detector v1.8            ║
║                  by M d h a l a H a t                    ║
╠══════════════════════════════════════════════════════════╣
║  Version: 1.8 | GitHub: github.com/mdhalahat             ║
║  Website: mdhalahat.com | Instagram: @mdhalahat          ║
║  Facebook: MdhalaHat | Tiktok: @mdhala.hat               ║
║  Linkedin: MdhalaHat                                     ║
╠══════════════════════════════════════════════════════════╣
║      ⚠️  FOR EDUCATIONAL & ETHICAL USE ONLY!            ║
║  Use only on websites you own or have permission to test.║
╠══════════════════════════════════════════════════════════╣
║              Made in Tunisia 🇹🇳                         ║
╚══════════════════════════════════════════════════════════╝
████████████████████████████████████████████████████████████
            """
        print(banner)
    
    def print_main_menu(self):
        """Display main interactive menu"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}M A I N   M E N U")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}🔗  URL Phishing Scanner  🔗")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.GREEN if COLORS_ENABLED else ''}📧  Email Phishing Scanner  📧")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.GREEN if COLORS_ENABLED else ''}🌐  IP Reputation Checker  🌐")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[4] {Fore.YELLOW if COLORS_ENABLED else ''}🛡️  File Malware Scanner  🛡️")  
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'-' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[5] {Fore.CYAN if COLORS_ENABLED else ''}📊  Phishing Intelligence Database  📊")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[6] {Fore.MAGENTA if COLORS_ENABLED else ''}🛡️  IP Intelligence Database  🛡️")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[7] {Fore.BLUE if COLORS_ENABLED else ''}📚  File Intelligence Database  📚")  
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'-' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[8] {Fore.YELLOW if COLORS_ENABLED else ''}About")  # Updated from 6 to 8
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Exit")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        while True:
            try:
                choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select an option (0-8): {Style.RESET_ALL if COLORS_ENABLED else ''}")  # Updated range
                choice = int(choice)
                if 0 <= choice <= 8:  #  range
                    return choice
                else:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid choice. Please enter 0-8.")  #  message
            except ValueError:
                print(f"{Fore.RED if COLORS_ENABLED else ''}Please enter a valid number.")

    
    def print_intelligence_menu(self):
        """Display phishing intelligence database menu"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📊 PHISHING INTELLIGENCE DATABASE")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}Run Web Scraping & Update Database")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.CYAN if COLORS_ENABLED else ''}View Database Statistics")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.YELLOW if COLORS_ENABLED else ''}View Recent Scraping History")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[4] {Fore.MAGENTA if COLORS_ENABLED else ''}Manually Update Patterns")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[5] {Fore.BLUE if COLORS_ENABLED else ''}View Top Detected Domains")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back to Main Menu")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        while True:
            try:
                choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select an option (0-5): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                choice = int(choice)
                if 0 <= choice <= 5:
                    return choice
                else:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid choice. Please enter 0-5.")
            except ValueError:
                print(f"{Fore.RED if COLORS_ENABLED else ''}Please enter a valid number.")
    
    def print_ip_intelligence_menu(self):
        """Display IP intelligence database menu"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}🛡️  IP INTELLIGENCE DATABASE")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.CYAN if COLORS_ENABLED else ''}Update Threat Feeds")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.YELLOW if COLORS_ENABLED else ''}View IP Statistics")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.MAGENTA if COLORS_ENABLED else ''}Check Multiple IPs")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back to Main Menu")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        while True:
            try:
                choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select an option (0-3): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                choice = int(choice)
                if 0 <= choice <= 3:
                    return choice
                else:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid choice. Please enter 0-3.")
            except ValueError:
                print(f"{Fore.RED if COLORS_ENABLED else ''}Please enter a valid number.")
    
    def run_intelligence_module(self):
        """Run the phishing intelligence database module"""
        while True:
            choice = self.print_intelligence_menu()
            
            if choice == 1:  # Run Web Scraping
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🌐 WEB SCRAPING OPTIONS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}Scrape All Active Sources")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.YELLOW if COLORS_ENABLED else ''}Scrape Specific Sources")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.CYAN if COLORS_ENABLED else ''}Test Single Source")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back")
                
                scrape_choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select scraping option: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                
                if scrape_choice == '1':
                    # Run scraping on all active sources
                    self.phishing_intel.run_scraping()
                    
                elif scrape_choice == '2':
                    # Show available sources
                    print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Available Sources:")
                    for i, source in enumerate(self.phishing_intel.scraping_sources.keys(), 1):
                        info = self.phishing_intel.scraping_sources[source]
                        status = "✓" if info['active'] else "✗"
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}  {i}. {status} {source} - {info['description']}")
                    
                    sources_input = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter source numbers (comma-separated): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    try:
                        indices = [int(x.strip()) - 1 for x in sources_input.split(',')]
                        sources = [list(self.phishing_intel.scraping_sources.keys())[i] for i in indices if 0 <= i < len(self.phishing_intel.scraping_sources)]
                        if sources:
                            self.phishing_intel.run_scraping(sources)
                        else:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}No valid sources selected.")
                    except:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid input.")
                
                elif scrape_choice == '3':
                    # Test single source
                    source = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter source name to test: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    if source in self.phishing_intel.scraping_sources:
                        success, urls, message = self.phishing_intel.fetch_from_source(source)
                        if success:
                            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Success: {message}")
                            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Found {len(urls)} URLs")
                            if urls:
                                print(f"{Fore.CYAN if COLORS_ENABLED else ''}Sample URLs:")
                                for url_data in urls[:5]:
                                    print(f"  - {url_data['full_url'][:80]}...")
                        else:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed: {message}")
                    else:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Source not found.")
            
            elif choice == 2:  # View Database Statistics
                stats = self.phishing_intel.get_database_statistics()
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📊 DATABASE STATISTICS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}📈 OVERVIEW")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}Total Subdomains: {stats['total_subdomains']}")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}Active Subdomains: {stats['active_subdomains']}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}📊 BY SOURCE")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                for source, count in stats['by_source'].items():
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{source:<20}: {Fore.CYAN if COLORS_ENABLED else ''}{count}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}🏆 TOP DOMAINS")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                for domain, count in stats['top_domains'][:10]:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}{domain:<30}: {Fore.YELLOW if COLORS_ENABLED else ''}{count}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}🔄 SCRAPING SUMMARY")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                scraping_stats = stats['scraping_summary']
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}Total Scrapes: {scraping_stats['total_scrapes']}")
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}Successful: {scraping_stats['successful']}")
                print(f"{Fore.RED if COLORS_ENABLED else ''}Failed: {scraping_stats['failed']}")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}Last Scrape: {scraping_stats['last_scrape']}")
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
            
            elif choice == 3:  # View Recent Scraping History
                history = self.phishing_intel.get_scraping_history(limit=20)
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📅 RECENT SCRAPING HISTORY")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                if not history:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}No scraping history found.")
                else:
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 100}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}{'Source':<15} {'Started':<20} {'Status':<12} {'Added':<8} {'Updated':<8} {'Error':<30}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 100}")
                    
                    for entry in history:
                        status_color = Fore.GREEN if entry['status'] == 'completed' else Fore.RED
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{entry['source']:<15} "
                              f"{entry['started'][:19]:<20} "
                              f"{status_color if COLORS_ENABLED else ''}{entry['status']:<12} "
                              f"{Fore.CYAN if COLORS_ENABLED else ''}{entry['added']:<8} "
                              f"{Fore.YELLOW if COLORS_ENABLED else ''}{entry['updated']:<8} "
                              f"{Fore.RED if COLORS_ENABLED else ''}{entry['error'] or '':<30}")
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
            
            elif choice == 4:  # Manually Update Patterns
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}✏️  MANUAL PATTERN MANAGEMENT")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}Add Custom Pattern")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.YELLOW if COLORS_ENABLED else ''}Add Subdomain from Clipboard")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.CYAN if COLORS_ENABLED else ''}Add Multiple Subdomains")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back")
                
                pattern_choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select option: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                
                if pattern_choice == '1':
                    pattern = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter pattern (regex or domain): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    category = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter category: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    risk_score = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter risk score (0-100): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    description = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter description: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                    
                    try:
                        risk_score = int(risk_score)
                        if self.phishing_intel.add_custom_pattern(pattern, category, risk_score, description):
                            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Pattern added successfully!")
                        else:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed to add pattern.")
                    except ValueError:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid risk score.")
                
                elif pattern_choice == '2':
                    try:
                        import pyperclip
                        clipboard = pyperclip.paste()
                        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', clipboard)
                        
                        if urls:
                            print(f"{Fore.GREEN if COLORS_ENABLED else ''}Found {len(urls)} URLs in clipboard")
                            for url in urls[:5]:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    # Add as custom pattern
                                    self.phishing_intel.add_custom_pattern(
                                        parsed.netloc,
                                        'manual',
                                        40,
                                        'Added from clipboard',
                                        'user'
                                    )
                                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}Added: {parsed.netloc}")
                        else:
                            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}No URLs found in clipboard")
                    except ImportError:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}pyperclip not installed. Install with: pip install pyperclip")
                
                elif pattern_choice == '3':
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Enter subdomains (one per line, empty line to finish):")
                    subdomains = []
                    while True:
                        line = input().strip()
                        if not line:
                            break
                        subdomains.append(line)
                    
                    added = 0
                    for subdomain in subdomains:
                        if self.phishing_intel.add_custom_pattern(subdomain, 'manual', 35, 'Manually added', 'user'):
                            added += 1
                    
                    print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ Added {added} subdomains")
            
            elif choice == 5:  # View Top Detected Domains
                top_domains = self.phishing_intel.get_top_detected_domains(limit=20)
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🏆 TOP DETECTED DOMAINS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                if not top_domains:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}No domain statistics available.")
                else:
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 80}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}{'Rank':<5} {'Domain':<30} {'Detections':<12} {'First Seen':<15} {'Risk':<10}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 80}")
                    
                    for i, domain_info in enumerate(top_domains, 1):
                        risk_color = Fore.RED if domain_info['risk_level'] == 'high' else Fore.YELLOW if domain_info['risk_level'] == 'medium' else Fore.GREEN
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{i:<5} "
                              f"{Fore.CYAN if COLORS_ENABLED else ''}{domain_info['domain']:<30} "
                              f"{Fore.YELLOW if COLORS_ENABLED else ''}{domain_info['detection_count']:<12} "
                              f"{Fore.WHITE if COLORS_ENABLED else ''}{domain_info['first_detected'][:10]:<15} "
                              f"{risk_color if COLORS_ENABLED else ''}{domain_info['risk_level']:<10}")
                    
                    # Show summary
                    total_detections = sum(d['detection_count'] for d in top_domains)
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 80}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Total Detections: {total_detections}")
                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}Unique Domains: {len(top_domains)}")
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
            
            elif choice == 0:  # Back to Main Menu
                break
            
            # Ask to continue in intelligence module
            if choice != 0:
                cont = input(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Return to Intelligence Menu? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                if cont.lower() != 'y':
                    break

    def run_ip_intelligence_module(self):
        """Run the IP intelligence database module"""
        while True:
            choice = self.print_ip_intelligence_menu()
            
            if choice == 1:  # Update Threat Feeds
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔄 UPDATE IP THREAT FEEDS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Updating IP threat feeds...")
                total_ips = self.ip_intel.update_threat_feeds()
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Update complete. Added/updated {total_ips} IP patterns.")
            
            elif choice == 2:  # View IP Statistics
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📊 IP STATISTICS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                conn = sqlite3.connect(self.ip_intel.db_path)
                cursor = conn.cursor()
                
                # Get total IPs
                cursor.execute('SELECT COUNT(*) FROM ip_reputation')
                total_ips = cursor.fetchone()[0]
                
                # Get blacklisted IPs
                cursor.execute('SELECT COUNT(*) FROM ip_reputation WHERE is_blacklisted = 1')
                blacklisted_ips = cursor.fetchone()[0]
                
                # Get threat level distribution
                cursor.execute('''
                SELECT threat_level, COUNT(*) as count
                FROM ip_reputation
                GROUP BY threat_level
                ORDER BY count DESC
                ''')
                threat_distribution = cursor.fetchall()
                
                # Get recent checks
                cursor.execute('''
                SELECT ip_address, reputation_score, threat_level, checked_at
                FROM ip_check_history
                ORDER BY checked_at DESC
                LIMIT 10
                ''')
                recent_checks = cursor.fetchall()
                
                conn.close()
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}📈 OVERVIEW")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}Total IPs in database: {total_ips}")
                print(f"{Fore.RED if COLORS_ENABLED else ''}Blacklisted IPs: {blacklisted_ips}")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}Blacklist rate: {blacklisted_ips/total_ips*100:.1f}%" if total_ips > 0 else "N/A")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚡ THREAT DISTRIBUTION")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                for threat_level, count in threat_distribution:
                    if threat_level == 'high':
                        color = Fore.RED
                    elif threat_level == 'medium':
                        color = Fore.YELLOW
                    elif threat_level == 'low':
                        color = Fore.GREEN
                    else:
                        color = Fore.WHITE
                    print(f"{color}{threat_level.upper():<10}: {count}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}🕐 RECENT CHECKS")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                for ip, score, level, checked in recent_checks:
                    if level == 'high':
                        color = Fore.RED
                    elif level == 'medium':
                        color = Fore.YELLOW
                    else:
                        color = Fore.GREEN
                    print(f"{color}{ip:<15} - Score: {score}/100 - {level.upper()}")
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
            
            elif choice == 3:  # Check Multiple IPs
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔍 CHECK MULTIPLE IPs")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Enter IP addresses (one per line, empty line to finish):")
                ip_list = []
                while True:
                    ip = input().strip()
                    if not ip:
                        break
                    ip_list.append(ip)
                
                if not ip_list:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No IP addresses provided.")
                    continue
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Checking {len(ip_list)} IP addresses...")
                
                results = []
                for i, ip in enumerate(ip_list, 1):
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}[{i}/{len(ip_list)}] Checking {ip}...")
                    reputation = self.ip_intel.check_ip_reputation(ip)
                    results.append(reputation)
                    
                    # Quick summary
                    score = reputation['score']
                    if score <= 30:
                        status = f"{Fore.GREEN}SAFE"
                    elif score <= 60:
                        status = f"{Fore.YELLOW}SUSPICIOUS"
                    else:
                        status = f"{Fore.RED}HIGH RISK"
                    
                    print(f"  Score: {score}/100 - {status}")
                    if reputation['is_blacklisted']:
                        print(f"  {Fore.RED}✗ Blacklisted")
                
                # Summary
                high_risk = sum(1 for r in results if r['score'] > 60)
                suspicious = sum(1 for r in results if 30 < r['score'] <= 60)
                safe = sum(1 for r in results if r['score'] <= 30)
                
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}📊 SUMMARY")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.RED if COLORS_ENABLED else ''}High Risk: {high_risk}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Suspicious: {suspicious}")
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}Safe: {safe}")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}Total: {len(ip_list)}")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            
            elif choice == 0:  # Back to Main Menu
                break
            
            # Ask to continue in IP intelligence module
            if choice != 0:
                cont = input(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Return to IP Intelligence Menu? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                if cont.lower() != 'y':
                    break

    def print_file_intelligence_menu(self):
        """Display file intelligence database menu"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📚 FILE INTELLIGENCE DATABASE")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}Update Threat Feeds")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.CYAN if COLORS_ENABLED else ''}View Database Statistics")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.YELLOW if COLORS_ENABLED else ''}View Recent Analyses")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[4] {Fore.MAGENTA if COLORS_ENABLED else ''}Add Custom Hash")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[5] {Fore.BLUE if COLORS_ENABLED else ''}Search Hash in Database")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back to Main Menu")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        while True:
            try:
                choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select an option (0-5): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                choice = int(choice)
                if 0 <= choice <= 5:
                    return choice
                else:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Invalid choice. Please enter 0-5.")
            except ValueError:
                print(f"{Fore.RED if COLORS_ENABLED else ''}Please enter a valid number.")

    # Method to run file intelligence module:
    def run_file_intelligence_module(self):
        """Run the file intelligence database module"""
        while True:
            choice = self.print_file_intelligence_menu()
            
            if choice == 1:  # Update Threat Feeds
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔄 UPDATE FILE THREAT FEEDS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Updating file threat feeds...")
                feed_results = self.file_intel.update_threat_feeds()
                
                print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ Update complete!")
                for feed, count in feed_results.items():
                    if count > 0:
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}  {feed}: {count} records added")
            
            elif choice == 2:  # View Database Statistics
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📊 FILE DATABASE STATISTICS")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                stats = self.file_intel.get_database_statistics()
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}📈 OVERVIEW")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}Total Hashes: {stats['total_hashes']}")
                
                if stats['hashes_by_source']:
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}📊 BY SOURCE")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    for source, count in stats['hashes_by_source'].items():
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{source:<20}: {Fore.CYAN if COLORS_ENABLED else ''}{count}")
                
                if stats['analysis_summary']:
                    analysis = stats['analysis_summary']
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}🔍 ANALYSIS HISTORY")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}Total Scans: {analysis['total_scans']}")
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Malicious: {analysis['malicious_detections']}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Suspicious: {analysis['suspicious_detections']}")
                    if analysis['last_scan']:
                        print(f"{Fore.CYAN if COLORS_ENABLED else ''}Last Scan: {analysis['last_scan']}")
                
                if stats['feed_status']:
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}🔄 THREAT FEEDS")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 40}")
                    for feed in stats['feed_status']:
                        status = "✓" if feed['is_active'] else "✗"
                        last_fetched = feed['last_fetched'] or "Never"
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{status} {feed['feed_name']:<15}: {feed['record_count']} records")
                        print(f"  Last fetched: {last_fetched}")
            
            elif choice == 3:  # View Recent Analyses
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📅 RECENT FILE ANALYSES")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                conn = sqlite3.connect(self.file_intel.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT filename, file_hash, analyzed_at, risk_score, threat_name
                FROM analysis_history
                ORDER BY analyzed_at DESC
                LIMIT 20
                ''')
                
                analyses = cursor.fetchall()
                
                if not analyses:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}No analysis history found.")
                else:
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 100}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}{'Filename':<30} {'Hash':<35} {'Date':<20} {'Risk':<10} {'Threat':<20}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 100}")
                    
                    for filename, file_hash, analyzed_at, risk_score, threat_name in analyses:
                        if risk_score > 60:
                            risk_color = Fore.RED
                        elif risk_score > 30:
                            risk_color = Fore.YELLOW
                        else:
                            risk_color = Fore.GREEN
                        
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{filename[:28]:<30} "
                            f"{file_hash[:8] if file_hash else 'N/A':<8}... "
                            f"{analyzed_at[:19] if analyzed_at else 'N/A':<20} "
                            f"{risk_color if COLORS_ENABLED else ''}{risk_score:<10} "
                            f"{threat_name or 'N/A':<20}")
                
                conn.close()
            
            elif choice == 4:  # Add Custom Hash
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}✏️ ADD CUSTOM MALWARE HASH")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                file_hash = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter file hash (MD5, SHA1, or SHA256): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                
                if not file_hash:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No hash provided.")
                    continue
                
                threat_name = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter threat name: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                source = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Enter source: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip() or "manual"
                
                if self.file_intel.add_hash_to_database(file_hash, threat_name, source):
                    print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Hash added to database")
                else:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed to add hash")
            
            elif choice == 5:  # Search Hash in Database
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔍 SEARCH HASH IN DATABASE")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                file_hash = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter file hash to search: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                
                if not file_hash:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No hash provided.")
                    continue
                
                found, intel_info = self.file_intel.check_hash_reputation(file_hash)
                
                if found:
                    print(f"\n{Fore.RED if COLORS_ENABLED else ''}🚨 HASH FOUND IN DATABASE!")
                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}Hash: {intel_info.get('hash')}")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Threat: {intel_info.get('threat_name', 'Unknown')}")
                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}Source: {intel_info.get('source', 'Unknown')}")
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}First Seen: {intel_info.get('first_seen', 'Unknown')}")
                    print(f"{Fore.RED if COLORS_ENABLED else ''}Risk Score: {intel_info.get('risk_score', 0)}/100")
                    print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                else:
                    print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ Hash not found in database")
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Note: This doesn't guarantee the file is safe")
            
            elif choice == 0:  # Back to Main Menu
                break
            
            # Ask to continue
            if choice != 0:
                cont = input(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Return to File Intelligence Menu? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                if cont.lower() != 'y':
                    break

    def ask_save_report(self) -> bool:
        """Ask user if they want to save a report"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        response = input(f"{Fore.YELLOW if COLORS_ENABLED else ''}💾 Save PDF report? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip().lower()
        return response == 'y'

def main():
    """Main application entry point"""
    try:
        # Initialize scanner
        scanner = MdhalaScan()
        url_scanner = URLScanner(scanner.phishing_intel, scanner.ip_intel)
        email_scanner = EmailScanner(scanner.phishing_intel, scanner.ip_intel)
        file_scanner = FileScanner(scanner.file_intel)  # NEW: File scanner
        presenter = ResultPresenter()
        
        # Display banner
        scanner.print_banner()
        
        while True:
            # Display main menu
            choice = scanner.print_main_menu()
            
            if choice == 1:  # URL Scanner
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🌐 URL PHISHING SCANNER")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                url = input(f"\n{Fore.GREEN if COLORS_ENABLED else ''}Enter URL to scan: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                
                if not url:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No URL provided. Returning to menu.")
                    continue
                
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                # Perform scan
                results = url_scanner.scan_url(url)
                
                # Display results
                presenter.display_url_results(results)
                
                # Ask to save report
                if scanner.ask_save_report():
                    try:
                        filepath = scanner.pdf_reporter.generate_url_report(results)
                        print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ PDF report saved: {filepath}")
                    except Exception as e:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Error generating PDF: {e}")
                        # Fallback to text report
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        safe_url = results.get('url', 'scan').replace('://', '_').replace('/', '_')[:50]
                        filename = f"url_scan_{safe_url}_{timestamp}.txt"
                        filepath = os.path.join("reports", filename)
                        with open(filepath, 'w') as f:
                            f.write(f"URL Scan Report\n")
                            f.write(f"URL: {results['url']}\n")
                            f.write(f"Risk Score: {results['risk_score']}/100\n")
                            f.write(f"Recommendation: {results['recommendation']}\n")
                        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Text report saved: {filepath}")
            
            elif choice == 2:  # Email Scanner
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📧 EMAIL PHISHING SCANNER")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Paste email headers (or press Enter to skip):")
                headers = ""
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                while True:
                    line = input()
                    if line.strip() == "":
                        break
                    headers += line + "\n"
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Paste email body:")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                body_lines = []
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}(Press Enter twice to finish)")
                while True:
                    try:
                        line = input()
                        if line == "" and len(body_lines) > 0 and body_lines[-1] == "":
                            break
                        body_lines.append(line)
                    except EOFError:
                        break
                body = "\n".join(body_lines)
                
                if not body.strip():
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No email body provided. Returning to menu.")
                    continue
                
                # Ask if user wants to scan embedded URLs
                scan_urls = True
                # Extract URLs to check if any exist
                temp_urls = email_scanner.extract_urls_from_text(body)
                if temp_urls:
                    print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Found {len(temp_urls)} URLs in email.")
                    response = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Scan these URLs? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip().lower()
                    scan_urls = response == 'y'
                else:
                    scan_urls = False
                
                # Perform scan
                results = email_scanner.scan_email(headers, body, scan_urls=scan_urls)
                
                # Display results
                presenter.display_email_results(results)
                
                # Ask to save report
                if scanner.ask_save_report():
                    try:
                        filepath = scanner.pdf_reporter.generate_email_report(results, headers, body)
                        print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ PDF report saved: {filepath}")
                    except Exception as e:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Error generating PDF: {e}")
                        # Fallback to text report
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"email_scan_{timestamp}.txt"
                        filepath = os.path.join("reports", filename)
                        with open(filepath, 'w') as f:
                            f.write(f"Email Scan Report\n")
                            f.write(f"Risk Score: {results['risk_score']}/100\n")
                            f.write(f"Detected URLs: {len(results.get('detected_urls', []))}\n")
                        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Text report saved: {filepath}")
            
            elif choice == 3:  # IP Reputation Checker (Simple IP Check)
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🔍 IP REPUTATION CHECKER")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                ip_address = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter IP address to check: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                
                if not ip_address:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}No IP address provided.")
                    continue
                
                print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Checking IP reputation...")
                
                # Check IP reputation
                reputation = scanner.ip_intel.check_ip_reputation(ip_address)
                
                # Display results
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}IP: {Fore.CYAN if COLORS_ENABLED else ''}{reputation['ip']}")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                
                # Risk score bar
                score = reputation['score']
                if score <= 30:
                    color = Fore.GREEN
                    level = "SAFE"
                elif score <= 60:
                    color = Fore.YELLOW
                    level = "SUSPICIOUS"
                else:
                    color = Fore.RED
                    level = "HIGH RISK"
                
                filled = int(score / 2)
                empty = 50 - filled
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}Reputation Score: {color}{score}/100")
                print(f"{color}{'█' * filled}{Fore.WHITE}{'░' * empty}")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}Threat Level: {color}{reputation['threat_level'].upper()}")
                
                # Blacklist status
                if reputation['is_blacklisted']:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}✗ IP is blacklisted in {len(reputation.get('details', {}).get('blocklists', []))} lists")
                else:
                    print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ IP is not blacklisted")
                
                # Sources checked
                if reputation['sources_checked']:
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}Sources checked: {', '.join(reputation['sources_checked'])}")
                
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                
                # Ask to save report
                if scanner.ask_save_report():
                    # Create a proper result structure for IP report
                    pdf_results = {
                        'scan_type': 'IP Reputation Check',
                        'ip_address': ip_address,
                        'risk_score': score,
                        'recommendation': f"IP appears {reputation['threat_level']} risk",
                        'ip_reputation': reputation,
                        'timestamp': datetime.now().isoformat(),
                        'scanner_version': scanner.version
                    }
                    
                    # Generate IP report - FIXED: Use generate_ip_report instead of generate_url_report
                    try:
                        filepath = scanner.pdf_reporter.generate_ip_report(pdf_results)
                        print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ PDF report saved: {filepath}")
                    except Exception as e:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Error generating PDF: {e}")
                        # Fallback to text report
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"ip_check_{ip_address}_{timestamp}.txt"
                        filepath = os.path.join("reports", filename)
                        with open(filepath, 'w') as f:
                            f.write(f"IP Reputation Check Report\n")
                            f.write(f"IP: {ip_address}\n")
                            f.write(f"Score: {score}/100\n")
                            f.write(f"Threat Level: {reputation['threat_level']}\n")
                        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Text report saved: {filepath}")
            
            elif choice == 4:  # NEW: File Malware Scanner
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}🛡️ FILE MALWARE SCANNER")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}[1] {Fore.GREEN if COLORS_ENABLED else ''}Scan Single File")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[2] {Fore.CYAN if COLORS_ENABLED else ''}Scan Directory")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[3] {Fore.YELLOW if COLORS_ENABLED else ''}Check File Hash")
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}[0] {Fore.RED if COLORS_ENABLED else ''}Back to Main Menu")
                
                file_choice = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Select option: {Style.RESET_ALL if COLORS_ENABLED else ''}")
                
                if file_choice == '1':  # Scan Single File
                    file_path = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter file path: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                    
                    if not os.path.exists(file_path):
                        print(f"{Fore.RED if COLORS_ENABLED else ''}File not found: {file_path}")
                        continue
                    
                    # Perform scan
                    results = file_scanner.scan_file(file_path)
                    
                    # Display results
                    presenter.display_file_results(results)
                    
                    # Ask to save report
                    if scanner.ask_save_report():
                        try:
                            filepath = scanner.pdf_reporter.generate_file_report(results)
                            print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ PDF report saved: {filepath}")
                        except Exception as e:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}Error generating PDF: {e}")
                    
                    # Ask to quarantine if high risk
                    if results['risk_score'] > 60:
                        quarantine = input(f"\n{Fore.RED if COLORS_ENABLED else ''}⚠️  Quarantine this high-risk file? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip().lower()
                        if quarantine == 'y':
                            if file_scanner.quarantine_file(file_path):
                                print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ File quarantined successfully")
                            else:
                                print(f"{Fore.RED if COLORS_ENABLED else ''}✗ Failed to quarantine file")
                
                elif file_choice == '2':  # Scan Directory
                    dir_path = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter directory path: {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                    
                    if not os.path.exists(dir_path):
                        print(f"{Fore.RED if COLORS_ENABLED else ''}Directory not found: {dir_path}")
                        continue
                    
                    recursive = input(f"{Fore.CYAN if COLORS_ENABLED else ''}Scan recursively? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip().lower()
                    
                    # Perform scan
                    results = file_scanner.scan_directory(dir_path, recursive=recursive == 'y')
                    
                    # Display results
                    presenter.display_directory_results(results)
                    
                    # Ask to save report
                    if scanner.ask_save_report():
                        try:
                            filepath = scanner.pdf_reporter.generate_directory_report(results)
                            print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ PDF report saved: {filepath}")
                        except Exception as e:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}Error generating PDF: {e}")
                
                elif file_choice == '3':  # Check File Hash
                    file_hash = input(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Enter file hash (MD5, SHA1, or SHA256): {Style.RESET_ALL if COLORS_ENABLED else ''}").strip()
                    
                    if not file_hash:
                        print(f"{Fore.RED if COLORS_ENABLED else ''}No hash provided.")
                        continue
                    
                    print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Checking hash reputation...")
                    
                    # Check against databases
                    found, intel_info = scanner.file_intel.check_hash_reputation(file_hash)
                    
                    if found:
                        print(f"\n{Fore.RED if COLORS_ENABLED else ''}🚨 HASH FOUND IN DATABASE!")
                        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Hash: {intel_info.get('hash')}")
                        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Threat: {intel_info.get('threat_name', 'Unknown')}")
                        print(f"{Fore.CYAN if COLORS_ENABLED else ''}Source: {intel_info.get('source', 'Unknown')}")
                        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
                    else:
                        print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✅ Hash not found in local database")
                        
                        # Check external APIs
                        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Checking external databases...")
                        ext_results = file_scanner.check_external_reputation(file_hash)
                        
                        if ext_results['malwarebazaar']['found']:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}❌ Found in MalwareBazaar database!")
                        if ext_results['threatfox']['found']:
                            print(f"{Fore.RED if COLORS_ENABLED else ''}❌ Found in ThreatFox database!")
                        
                        if not (ext_results['malwarebazaar']['found'] or ext_results['threatfox']['found']):
                            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Hash not found in external databases")

            elif choice == 5:  # Phishing Intelligence Database
                scanner.run_intelligence_module()
            
            elif choice == 6:  # IP Intelligence Database
                scanner.run_ip_intelligence_module()
            
            
            
            elif choice == 7:  # NEW: File Intelligence Database
                scanner.run_file_intelligence_module()

            elif choice == 8:  # About & Documentation
                print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📖 ABOUT MdhalaScan v1.8")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
                print(f"""
{Fore.WHITE if COLORS_ENABLED else ''}MdhalaScan v1.0 - Advanced Scanning Tool
{Fore.GREEN if COLORS_ENABLED else ''}• Detects phishing URLs and emails
{Fore.GREEN if COLORS_ENABLED else ''}• IP reputation checking and analysis
{Fore.GREEN if COLORS_ENABLED else ''}• Professional PDF report generation
{Fore.GREEN if COLORS_ENABLED else ''}• Phishing Intelligence Database with web scraping
{Fore.GREEN if COLORS_ENABLED else ''}• IP Intelligence Database with threat feeds
{Fore.GREEN if COLORS_ENABLED else ''}• Analyzes embedded URLs in emails
{Fore.GREEN if COLORS_ENABLED else ''}• Real-time threat intelligence integration
{Fore.GREEN if COLORS_ENABLED else ''}• Educates users about phishing indicators
{Fore.GREEN if COLORS_ENABLED else ''}• Provides clear risk assessments
{Fore.WHITE if COLORS_ENABLED else ''}• Professional PDF report generation
{Fore.WHITE if COLORS_ENABLED else ''}• IP reputation checking (Spamhaus, FireHOL, ThreatFox)
{Fore.WHITE if COLORS_ENABLED else ''}• IP Intelligence Database
{Fore.WHITE if COLORS_ENABLED else ''}• Enhanced threat intelligence
{Fore.WHITE if COLORS_ENABLED else ''}• Improved accuracy and performance

{Fore.YELLOW if COLORS_ENABLED else ''}KEY FEATURES:
{Fore.WHITE if COLORS_ENABLED else ''}• Multi-layer URL analysis
{Fore.WHITE if COLORS_ENABLED else ''}• Email header and content scanning
{Fore.WHITE if COLORS_ENABLED else ''}• Risk scoring (0-100)
{Fore.WHITE if COLORS_ENABLED else ''}• Detailed findings with explanations
{Fore.WHITE if COLORS_ENABLED else ''}• URL analysis within emails
{Fore.WHITE if COLORS_ENABLED else ''}• Phishing database with 6+ sources
{Fore.WHITE if COLORS_ENABLED else ''}• IP reputation with 8+ sources
{Fore.WHITE if COLORS_ENABLED else ''}• Professional PDF reports
{Fore.WHITE if COLORS_ENABLED else ''}• Historical detection tracking

{Fore.CYAN if COLORS_ENABLED else ''}IP REPUTATION SOURCES:
{Fore.WHITE if COLORS_ENABLED else ''}• Spamhaus DROP/EDROP lists
{Fore.WHITE if COLORS_ENABLED else ''}• FireHOL Level 1 blocklist
{Fore.WHITE if COLORS_ENABLED else ''}• Abuse.ch ThreatFox
{Fore.WHITE if COLORS_ENABLED else ''}• AlienVault OTX (free)
{Fore.WHITE if COLORS_ENABLED else ''}• AbuseIPDB (API key required)
{Fore.WHITE if COLORS_ENABLED else ''}• VirusTotal (API key required)

{Fore.RED if COLORS_ENABLED else ''}IMPORTANT:
{Fore.WHITE if COLORS_ENABLED else ''}• Use only on systems you own or have permission to test
{Fore.WHITE if COLORS_ENABLED else ''}• This tool is for defensive/educational purposes only
{Fore.WHITE if COLORS_ENABLED else ''}• Results should be verified by security professionals
{Fore.WHITE if COLORS_ENABLED else ''}• Reports may contain sensitive information - handle securely

{Fore.CYAN if COLORS_ENABLED else ''}Created by: {Fore.MAGENTA if COLORS_ENABLED else ''}MdhalaHat
{Fore.CYAN if COLORS_ENABLED else ''}Version: {Fore.GREEN if COLORS_ENABLED else ''}1.8
{Fore.CYAN if COLORS_ENABLED else ''}License: Educational Use
                """)
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
            


            elif choice == 0:  # Exit
                print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}Thank you for using MdhalaScan !")
                print(f"{Fore.CYAN if COLORS_ENABLED else ''}Stay secure! 👋\n")
                break
            
            # Ask to continue
            if choice != 0:
                cont = input(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}Return to Main Menu? (y/n): {Style.RESET_ALL if COLORS_ENABLED else ''}")
                if cont.lower() != 'y':
                    print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}Thank you for using MdhalaScan !")
                    print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}Goodbye! Stay secure! 👋\n")
                    break
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW if COLORS_ENABLED else ''}Scan interrupted.")
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}Thank you for using MdhalaScan !\n")
    except Exception as e:
        print(f"\n{Fore.RED if COLORS_ENABLED else ''}Error: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Please report issues to the developer.")

if __name__ == "__main__":
    # Check and install dependencies
    required_packages = ['requests', 'beautifulsoup4', 'tldextract']
    
    # NEW: File scanner dependencies (optional)
    optional_packages = [
        'yara-python',
        'python-magic',
        'pefile',
        'oletools',
        'pdfminer.six',
        'ssdeep',
        'pyzipper'
    ]
    
    print(f"{Fore.CYAN if COLORS_ENABLED else ''}Checking dependencies...")
    
    # Check required packages
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ {package}")
        except ImportError:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ Installing {package}...")
            import subprocess
            subprocess.call([sys.executable, '-m', 'pip', 'install', package])
    
    # Check optional packages for file scanning
    print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}Checking file scanner dependencies...")
    for package in optional_packages:
        try:
            __import__(package.replace('-', '_').replace('.', '_'))
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ {package}")
        except ImportError:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ Optional: {package} not installed")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}   Install with: pip install {package}")
            if package == 'yara-python':
                print(f"{Fore.WHITE if COLORS_ENABLED else ''}   Note: YARA may require system libraries (libyara-dev)")
    
    # Check for PDF library
    try:
        from reportlab.lib.pagesizes import letter
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}✓ reportlab (PDF support available)")
    except ImportError:
        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠ Optional: PDF report generation requires 'reportlab'")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}   Install with: pip install reportlab")
    
    print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}All core dependencies satisfied!")
    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Note: File scanner features are enhanced with optional packages")
    print(f"{Fore.CYAN if COLORS_ENABLED else ''}Starting MdhalaScan ...\n")
    
    # Create reports directory
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    # Create quarantine directory
    if not os.path.exists("quarantine"):
        os.makedirs("quarantine")
    
    main()
