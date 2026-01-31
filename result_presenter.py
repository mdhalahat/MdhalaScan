"""
MdhalaScan - Result Presenter Module
Display scan results with visual progress bars
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

# Import from utils
from utils import Fore, COLORS_ENABLED, Style, ProgressBar

class ResultPresenter:
    """Updated presenter to show phishing intelligence and IP reputation warnings"""
    
    def __init__(self):
        self.progress_bar = ProgressBar()
    
    def display_url_details(self, url_details: Dict):
        """Display URL details in a formatted table"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}📋 URL DETAILS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        # Create formatted output
        details_display = f"""
{Fore.WHITE if COLORS_ENABLED else ''}{'Domain:':<20} {Fore.CYAN if COLORS_ENABLED else ''}{url_details.get('domain', 'N/A')}
{Fore.WHITE if COLORS_ENABLED else ''}{'Main Domain:':<20} {Fore.CYAN if COLORS_ENABLED else ''}{url_details.get('main_domain', 'N/A')}
{Fore.WHITE if COLORS_ENABLED else ''}{'TLD:':<20} {Fore.CYAN if COLORS_ENABLED else ''}{url_details.get('tld', 'N/A')}
{Fore.WHITE if COLORS_ENABLED else ''}{'Subdomain Count:':<20} {Fore.CYAN if COLORS_ENABLED else ''}{url_details.get('subdomain_count', 0)}
{Fore.WHITE if COLORS_ENABLED else ''}{'HTTPS:':<20} {Fore.GREEN if url_details.get('https') and COLORS_ENABLED else Fore.RED if COLORS_ENABLED else ''}{url_details.get('https', False)}
{Fore.WHITE if COLORS_ENABLED else ''}{'IP Address:':<20} {Fore.CYAN if COLORS_ENABLED else ''}{url_details.get('ip_address', 'N/A')}
"""
        print(details_display)
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
    
    def display_url_results(self, results: Dict):
        """Display URL scan results with visual progress bar"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📊 ENHANCED URL SCAN RESULTS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        risk_score = results['risk_score']
        
        # Show phishing intelligence warning FIRST if present
        if results.get('phishing_intelligence_match'):
            intel_info = results.get('intel_info', {})
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}{'🚨' * 30}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}🚨 PHISHING INTELLIGENCE MATCH!")
            if intel_info.get('match_type') == 'exact':
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Subdomain: {intel_info.get('subdomain')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Source: {intel_info.get('source')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Detected: {intel_info.get('detection_count', 0)} times")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}First seen: {intel_info.get('first_seen', 'Unknown')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Last seen: {intel_info.get('last_seen', 'Unknown')}")
            elif intel_info.get('match_type') == 'domain':
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Domain: {intel_info.get('domain')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Sources: {', '.join(intel_info.get('sources', []))}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Total detections: {intel_info.get('detection_count', 0)}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Risk level: {intel_info.get('risk_level', 'medium')}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{'🚨' * 30}")
        
        # Show abused infrastructure warning
        if results.get('abused_infrastructure'):
            abuse_info = results.get('abuse_info', {})
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}{'⚠' * 60}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}🚨 ABUSED INFRASTRUCTURE DETECTED!")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Category: {abuse_info.get('category', 'Unknown')}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Risk: {abuse_info.get('risk_score', 0)} points")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Description: {abuse_info.get('description', '')}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{'⚠' * 60}")
        
        # Show IP reputation warning
        if results.get('ip_reputation'):
            ip_reputation = results['ip_reputation']
            if ip_reputation.get('is_blacklisted') or ip_reputation.get('threat_level') == 'high':
                print(f"\n{Fore.RED if COLORS_ENABLED else ''}{'⚠' * 60}")
                print(f"{Fore.RED if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}🚨 IP REPUTATION ALERT!")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}IP Address: {ip_reputation.get('ip', 'Unknown')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Threat Level: {ip_reputation.get('threat_level', 'Unknown').upper()}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Reputation Score: {ip_reputation.get('score', 0)}/100")
                if ip_reputation.get('is_blacklisted'):
                    print(f"{Fore.RED if COLORS_ENABLED else ''}✗ IP IS BLACKLISTED")
                print(f"{Fore.RED if COLORS_ENABLED else ''}{'⚠' * 60}")
        
        # Display trusted domain info if applicable
        if results.get('trusted_domain'):
            category = results.get('domain_category', 'Trusted')
            print(f"\n{Fore.GREEN if COLORS_ENABLED else ''}✓ {category} Domain Detected")
        
        # Display URL details
        if results.get('url_details'):
            self.display_url_details(results['url_details'])
        
        # Display risk score with progress bar
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}URL: {results['url']}")
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}THREAT ASSESSMENT:")
        print(f"{self.progress_bar.create_risk_bar(risk_score)}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        
        # Show breakdown if available
        if results.get('breakdown'):
            print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}📈 RISK BREAKDOWN:")
            print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            
            breakdown = results['breakdown']
            for category, score in breakdown.items():
                if score > 0:
                    category_name = category.replace('_', ' ').title()
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}{category_name:<25}: {Fore.YELLOW if COLORS_ENABLED else ''}+{score}")

        # Add phishing intelligence to breakdown if present
        if results.get('phishing_intelligence_match'):
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}🚨 PHISHING INTELLIGENCE:")
            intel_info = results.get('intel_info', {})
            if intel_info.get('match_type') == 'exact':
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Subdomain: {intel_info.get('subdomain')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Source: {intel_info.get('source')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Detection Count: {intel_info.get('detection_count')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Risk Score: +{intel_info.get('risk_score', 60)} points")
            elif intel_info.get('match_type') == 'domain':
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Domain: {intel_info.get('domain')}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Sources: {', '.join(intel_info.get('sources', []))}")
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Total Detections: {intel_info.get('detection_count')}")
        
        # Add abused infrastructure to breakdown if present
        if results.get('abused_infrastructure'):
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}🚨 ABUSED INFRASTRUCTURE ANALYSIS:")
            abuse_info = results.get('abuse_info', {})
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Category: {abuse_info.get('category')}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Risk Score: +{abuse_info.get('risk_score', 0)} points")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}  Description: {abuse_info.get('description')}")
        
        # Add IP reputation to breakdown if present
        if results.get('ip_reputation'):
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}🌐 IP REPUTATION ANALYSIS:")
            ip_reputation = results['ip_reputation']
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  IP Address: {ip_reputation.get('ip')}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Reputation Score: {ip_reputation.get('score')}/100")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Threat Level: {ip_reputation.get('threat_level', 'unknown').upper()}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Blacklisted: {'Yes' if ip_reputation.get('is_blacklisted') else 'No'}")
            if ip_reputation.get('sources_checked'):
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Sources Checked: {', '.join(ip_reputation['sources_checked'])}")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}🔍 DETECTED INDICATORS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if results['findings']:
            for finding in results['findings']:
                print(f"  {finding}")
        else:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ✓ No significant threats detected")
        
        # Determine recommendations based on risk level
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}💡 RECOMMENDATIONS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if risk_score <= 30:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    ✅  URL APPEARS SAFE              │")
            if results.get('trusted_domain'):
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Trusted domain verified       │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Continue with normal caution    │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Standard security practices     │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        elif risk_score <= 60:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    ⚠️   EXERCISE CAUTION              │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Verify website legitimacy       │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Don't enter sensitive info      │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Check HTTPS & certificate       │")
            if results.get('phishing_intelligence_match'):
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Domain in phishing database   │")
            if results.get('abused_infrastructure'):
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Suspicious hosting detected   │")
            if results.get('ip_reputation') and results['ip_reputation'].get('threat_level') in ['medium', 'high']:
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Poor IP reputation           │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        else:
            print(f"{Fore.RED if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    ⚠️   HIGH RISK DETECTED             │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • DO NOT enter information        │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • DO NOT download files           │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Close page immediately          │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Report to IT security           │")
            if results.get('phishing_intelligence_match'):
                print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Known phishing domain         │")
            if results.get('abused_infrastructure'):
                print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Hosted on abused platform     │")
            if results.get('ip_reputation') and results['ip_reputation'].get('is_blacklisted'):
                print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • IP is blacklisted            │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
    
    def display_email_results(self, results: Dict):
        """Display email scan results with visual progress bar"""
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📧 EMAIL SCAN RESULTS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        risk_score = results['risk_score']
        
        # Display risk score with progress bar
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}THREAT ASSESSMENT:")
        print(f"{self.progress_bar.create_risk_bar(risk_score)}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        
        # Show URL scan summary if available
        if results.get('url_scan_results'):
            url_results = results['url_scan_results']
            print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}🔗 EMBEDDED URL ANALYSIS:")
            print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}  Total URLs detected: {url_results['total_urls']}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}  URLs scanned: {url_results['scanned_urls']}")
            
            # Show URL risk bars
            if url_results['safe_urls'] > 0:
                print(f"{Fore.GREEN if COLORS_ENABLED else ''}  Safe URLs:    {self.progress_bar.create_risk_bar(0, 10).replace('0%', str(url_results['safe_urls']))}")
            if url_results['suspicious_urls'] > 0:
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Suspicious:   {self.progress_bar.create_risk_bar(45, 10).replace('45%', str(url_results['suspicious_urls']))}")
            if url_results['high_risk_urls'] > 0:
                print(f"{Fore.RED if COLORS_ENABLED else ''}  High-risk:    {self.progress_bar.create_risk_bar(85, 10).replace('85%', str(url_results['high_risk_urls']))}")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}🔍 DETECTED INDICATORS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if results['findings']:
            for finding in results['findings']:
                print(f"  {finding}")
        else:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ✓ No significant threats detected")
        
        # Display recommendations with visual boxes
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}💡 SECURITY RECOMMENDATIONS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if risk_score <= 30:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    ✅  EMAIL APPEARS LEGITIMATE      │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Continue with normal caution    │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Verify sender if uncertain      │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        elif risk_score <= 60:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    ⚠️   SUSPICIOUS EMAIL              │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Do not click any links         │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Verify sender identity         │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Don't download attachments     │")
            if results.get('detected_urls'):
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Avoid {len(results['detected_urls'])} embedded URLs   │")
            if results.get('url_scan_results') and results['url_scan_results']['high_risk_urls'] > 0:
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Contains phishing URLs      │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        else:
            print(f"{Fore.RED if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    ⚠️   HIGH RISK PHISHING EMAIL       │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • DELETE this email immediately   │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • DO NOT reply or click anything  │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Report to IT/security team      │")
            if results.get('url_scan_results') and results['url_scan_results']['high_risk_urls'] > 0:
                print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Contains {results['url_scan_results']['high_risk_urls']} high-risk URLs │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")

# Result for file scan =============================================================

    def display_file_results(self, results: Dict):
        """Display file scan results with visual progress bar"""
        if 'error' in results:
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}Error: {results['error']}")
            return
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📊 FILE SCAN RESULTS")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        risk_score = results['risk_score']
        
        # Display file information
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}📄 FILE INFORMATION:")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Filename: {results['filename']}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}Size: {results['file_size']:,} bytes")
        
        if results['hashes']:
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}MD5: {results['hashes'].get('md5', 'N/A')}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}SHA256: {results['hashes'].get('sha256', 'N/A')}")
        
        if results['file_type']:
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Type: {results['file_type'].get('detected_type', 'Unknown')}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}Extension: .{results['file_type'].get('extension', 'N/A')}")
        
        # Display hash match warning
        if results.get('hash_match'):
            intel_info = results.get('intel_info', {})
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}{'🚨' * 30}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}🚨 KNOWN MALWARE DETECTED!")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Threat Name: {intel_info.get('threat_name', 'Unknown')}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}Source: {intel_info.get('source', 'Unknown')}")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}First Seen: {intel_info.get('first_seen', 'Unknown')}")
            print(f"{Fore.RED if COLORS_ENABLED else ''}{'🚨' * 30}")
        
        # Display external reputation matches
        ext_rep = results.get('external_reputation', {})
        if ext_rep.get('malwarebazaar', {}).get('found'):
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}❌ File found in MalwareBazaar database")
        if ext_rep.get('threatfox', {}).get('found'):
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}❌ File found in ThreatFox database")
        
        # Display risk score with progress bar
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}THREAT ASSESSMENT:")
        print(f"{self.progress_bar.create_risk_bar(risk_score)}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}{'─' * 60}")
        
        # Display findings
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}🔍 DETECTED INDICATORS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if results['findings']:
            for finding in results['findings']:
                if '❌' in finding:
                    print(f"{Fore.RED if COLORS_ENABLED else ''}  {finding}")
                elif '⚠️' in finding:
                    print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  {finding}")
                else:
                    print(f"{Fore.WHITE if COLORS_ENABLED else ''}  {finding}")
        else:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ✓ No significant threats detected")
        
        # Display YARA matches
        if results.get('yara_matches'):
            print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            print(f"{Fore.WHITE if COLORS_ENABLED else ''}🛡️ YARA RULE MATCHES:")
            print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            for match in results['yara_matches']:
                print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  • {match['rule']}")
        
        # Display analysis details
        if results.get('analysis_results'):
            analysis = results['analysis_results']
            
            if 'entropy' in analysis:
                entropy = analysis['entropy']
                print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}Entropy: {entropy:.2f} ", end="")
                if entropy > 7.5:
                    print(f"{Fore.RED}(High)")
                elif entropy > 6.5:
                    print(f"{Fore.YELLOW}(Moderate)")
                else:
                    print(f"{Fore.GREEN}(Normal)")
            
            # PE Analysis summary
            if 'pe_analysis' in analysis:
                pe_info = analysis['pe_analysis']
                if pe_info.get('is_pe'):
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}PE Analysis:")
                    print(f"  Sections: {len(pe_info.get('sections', []))}")
                    print(f"  Imports: {len(pe_info.get('imports', []))}")
            
            # PDF Analysis summary
            if 'pdf_analysis' in analysis:
                pdf_info = analysis['pdf_analysis']
                if pdf_info.get('is_pdf'):
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}PDF Analysis:")
                    if pdf_info.get('javascript_found'):
                        print(f"{Fore.YELLOW}  JavaScript: Yes")
                    if pdf_info.get('auto_action_found'):
                        print(f"{Fore.YELLOW}  Auto Actions: Yes")
            
            # Office Analysis summary
            if 'office_analysis' in analysis:
                office_info = analysis['office_analysis']
                if office_info.get('is_office'):
                    print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}Office Analysis:")
                    if office_info.get('has_macros'):
                        print(f"{Fore.YELLOW}  Macros: Yes")
                        if office_info.get('suspicious_macros'):
                            print(f"{Fore.RED}  Suspicious Macros: {', '.join(office_info['suspicious_macros'])}")
        
        # Display recommendations
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}💡 SECURITY RECOMMENDATIONS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if risk_score <= 30:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    ✅  FILE APPEARS SAFE             │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Safe for normal use            │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  │    • Standard precautions advised   │")
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        elif risk_score <= 60:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    ⚠️   EXERCISE CAUTION              │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Scan with antivirus first       │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Open in sandbox if needed       │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  │    • Don't run with admin rights     │")
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        else:
            print(f"{Fore.RED if COLORS_ENABLED else ''}  ┌──────────────────────────────────────┐")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    ⚠️   HIGH RISK - DO NOT OPEN!       │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • DELETE file immediately         │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Run full system scan            │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Report to IT security           │")
            if results.get('hash_match'):
                print(f"{Fore.RED if COLORS_ENABLED else ''}  │    • Known malware signature       │")
            print(f"{Fore.RED if COLORS_ENABLED else ''}  └──────────────────────────────────────┘")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
    
    def display_directory_results(self, results: Dict):
        """Display directory scan summary results"""
        if 'error' in results:
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}Error: {results['error']}")
            return
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        print(f"{Fore.MAGENTA if COLORS_ENABLED else ''}{Style.BRIGHT if COLORS_ENABLED else ''}📁 DIRECTORY SCAN SUMMARY")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")
        
        print(f"\n{Fore.WHITE if COLORS_ENABLED else ''}Directory: {results['directory']}")
        print(f"Scan Time: {results['scan_time']}")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        # Statistics
        total = results['total_files']
        scanned = results['scanned_files']
        malicious = results['malicious_files']
        suspicious = results['suspicious_files']
        safe = results['safe_files']
        
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}📊 STATISTICS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.GREEN if COLORS_ENABLED else ''}  Safe Files:      {safe}")
        print(f"{Fore.YELLOW if COLORS_ENABLED else ''}  Suspicious:      {suspicious}")
        print(f"{Fore.RED if COLORS_ENABLED else ''}  Malicious:       {malicious}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}  Total Scanned:   {scanned}/{total}")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        # Show malicious files
        if malicious > 0:
            print(f"\n{Fore.RED if COLORS_ENABLED else ''}🚨 MALICIOUS FILES DETECTED:")
            print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            for file_result in results['file_results']:
                if file_result['risk_score'] > 60:
                    print(f"{Fore.RED}✗ {file_result['filename']} - {file_result['risk_score']}% risk")
                    if file_result.get('threat_name') and file_result['threat_name'] != 'Unknown':
                        print(f"   Threat: {file_result['threat_name']}")
        
        # Show suspicious files
        if suspicious > 0:
            print(f"\n{Fore.YELLOW if COLORS_ENABLED else ''}⚠️ SUSPICIOUS FILES:")
            print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
            for file_result in results['file_results']:
                if 30 < file_result['risk_score'] <= 60:
                    print(f"{Fore.YELLOW}⚠ {file_result['filename']} - {file_result['risk_score']}% risk")
        
        # Recommendations
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        print(f"{Fore.WHITE if COLORS_ENABLED else ''}💡 RECOMMENDATIONS:")
        print(f"{Fore.CYAN if COLORS_ENABLED else ''}{'─' * 40}")
        
        if malicious == 0 and suspicious == 0:
            print(f"{Fore.GREEN if COLORS_ENABLED else ''}✅ Directory appears clean")
            print(f"   Continue with normal security practices")
        elif malicious == 0:
            print(f"{Fore.YELLOW if COLORS_ENABLED else ''}⚠️ Suspicious files found")
            print(f"   Review suspicious files before opening")
            print(f"   Consider scanning with antivirus software")
        else:
            print(f"{Fore.RED if COLORS_ENABLED else ''}🚨 MALICIOUS FILES PRESENT!")
            print(f"   1. Isolate affected system if possible")
            print(f"   2. Delete all malicious files immediately")
            print(f"   3. Run full system antivirus scan")
            print(f"   4. Monitor for unusual activity")
        
        print(f"\n{Fore.CYAN if COLORS_ENABLED else ''}{'═' * 60}")