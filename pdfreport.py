"""
MdhalaScan - PDF Report Generator Module
Generates professional PDF reports for scan results
"""

import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# Try to import PDF libraries
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch, cm
    from reportlab.pdfgen import canvas
    from reportlab.graphics.shapes import Drawing, Line
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class PDFReportGenerator:
    """Generate professional PDF reports for scan results"""

    def __init__(self):
        self.reports_dir = "reports"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        if REPORTLAB_AVAILABLE:
            # Create styles
            self.styles = getSampleStyleSheet()
            
            # Custom styles
            self.title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            self.subtitle_style = ParagraphStyle(
                'CustomSubtitle',
                parent=self.styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#34495e'),
                spaceAfter=20
            )
            
            self.normal_style = ParagraphStyle(
                'CustomNormal',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=6
            )
            
            self.highlight_style = ParagraphStyle(
                'CustomHighlight',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#e74c3c'),
                backColor=colors.HexColor('#fdf2f2'),
                borderPadding=5,
                borderColor=colors.HexColor('#e74c3c'),
                borderWidth=1,
                spaceAfter=6
            )
            
            self.good_style = ParagraphStyle(
                'CustomGood',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#27ae60'),
                spaceAfter=6
            )
            
            self.warning_style = ParagraphStyle(
                'CustomWarning',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#f39c12'),
                spaceAfter=6
            )
    
    def _get_risk_color(self, score: int) -> colors.Color:
        """Get color based on risk score"""
        if score <= 30:
            return colors.HexColor('#27ae60')  # Green
        elif score <= 60:
            return colors.HexColor('#f39c12')  # Yellow/Orange
        else:
            return colors.HexColor('#e74c3c')  # Red
    
    def _create_header_footer(self, canvas, doc, scan_type: str = "Security Scan"):
        """Create header and footer for PDF pages"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.HexColor('#2c3e50'))
        canvas.drawString(inch, doc.height + inch + 0.5*inch, f"MdhalaScan - {scan_type} Report")
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#7f8c8d'))
        canvas.drawString(inch, doc.height + inch + 0.35*inch, "Confidential - For authorized use only")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#7f8c8d'))
        canvas.drawString(inch, 0.5*inch, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawRightString(doc.width + inch, 0.5*inch, f"Page {canvas.getPageNumber()}")
        
        # Line separator
        canvas.setStrokeColor(colors.HexColor('#3498db'))
        canvas.setLineWidth(0.5)
        canvas.line(inch, doc.height + inch + 0.25*inch, doc.width + inch, doc.height + inch + 0.25*inch)
        canvas.line(inch, 0.75*inch, doc.width + inch, 0.75*inch)
        
        canvas.restoreState()
    
    def _create_risk_meter(self, score: int) -> Drawing:
        """Create a visual risk meter for PDF"""
        drawing = Drawing(400, 100)
        
        # Background bar
        bg_bar = Drawing(300, 20)
        bg_bar.add(Line(0, 10, 300, 10, strokeColor=colors.lightgrey, strokeWidth=15))
        
        # Risk bar
        risk_width = 300 * score / 100
        risk_bar = Drawing(risk_width, 20)
        risk_color = self._get_risk_color(score)
        risk_bar.add(Line(0, 10, risk_width, 10, strokeColor=risk_color, strokeWidth=15))
        
        # Labels
        drawing.add(bg_bar)
        drawing.add(risk_bar)
        
        # Add text labels
        from reportlab.graphics.shapes import String
        drawing.add(String(0, 40, "Low Risk", fontSize=8, fillColor=colors.HexColor('#27ae60')))
        drawing.add(String(135, 40, "Medium Risk", fontSize=8, fillColor=colors.HexColor('#f39c12')))
        drawing.add(String(270, 40, "High Risk", fontSize=8, fillColor=colors.HexColor('#e74c3c')))
        
        # Score text
        drawing.add(String(150, 60, f"Risk Score: {score}/100", fontSize=12, fillColor=risk_color, fontName='Helvetica-Bold'))
        
        return drawing
    
    def _create_summary_table(self, results: Dict, scan_type: str = "Scan") -> Table:
        """Create summary table for report"""
        data = []
        
        # Basic info
        data.append(["Scan Information", ""])
        data.append(["Scan Type", results.get('scan_type', scan_type)])
        
        # Add appropriate target based on scan type
        if 'url' in results:
            data.append(["Target URL", results.get('url', 'N/A')])
        elif 'ip_address' in results:
            data.append(["Target IP", results.get('ip_address', 'N/A')])
        elif 'email_subject' in results:
            data.append(["Email Subject", results.get('email_subject', 'N/A')])
        else:
            data.append(["Target", results.get('target', 'N/A')])
            
        data.append(["Scan Date", results.get('timestamp', datetime.now().isoformat())])
        data.append(["Scanner Version", results.get('scanner_version', '1.8')])
        
        # Risk info
        risk_score = results.get('risk_score', 0)
        risk_color = self._get_risk_color(risk_score)
        data.append(["", ""])
        data.append(["Risk Assessment", ""])
        data.append(["Overall Risk Score", f"{risk_score}/100"])
        
        if risk_score <= 30:
            risk_level = "LOW - Likely Safe"
        elif risk_score <= 60:
            risk_level = "MEDIUM - Exercise Caution"
        else:
            risk_level = "HIGH - Probable Threat"
        
        data.append(["Risk Level", risk_level])
        data.append(["Recommendation", results.get('recommendation', 'N/A')])
        
        # Table styling
        table = Table(data, colWidths=[200, 250])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2c3e50')),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Color the risk level cell
        for i, row in enumerate(data):
            if row[0] == "Risk Level":
                table.setStyle(TableStyle([
                    ('BACKGROUND', (1, i), (1, i), risk_color),
                    ('TEXTCOLOR', (1, i), (1, i), colors.white),
                ]))
                break
        
        return table
    
    def generate_url_report(self, results: Dict) -> str:
        """Generate PDF report for URL scan"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results, 'url')
        
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = results.get('url', 'scan').replace('://', '_').replace('/', '_')[:50]
        filename = f"url_scan_{safe_url}_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("MdhalaScan Security Scan Report", self.title_style))
        story.append(Paragraph("URL Analysis Report", self.subtitle_style))
        story.append(Spacer(1, 20))
        
        # Risk Meter
        risk_score = results.get('risk_score', 0)
        story.append(self._create_risk_meter(risk_score))
        story.append(Spacer(1, 30))
        
        # Summary Table
        results['scan_type'] = 'URL Analysis'
        story.append(self._create_summary_table(results, 'URL Analysis'))
        story.append(Spacer(1, 30))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.subtitle_style))
        
        findings = results.get('findings', [])
        if findings:
            for finding in findings:
                if '❌' in finding or 'HIGH RISK' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.highlight_style))
                elif '⚠️' in finding or 'SUSPICIOUS' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.warning_style))
                elif '✓' in finding:
                    story.append(Paragraph(f"• {finding}", self.good_style))
                else:
                    story.append(Paragraph(f"• {finding}", self.normal_style))
        else:
            story.append(Paragraph("No significant findings detected.", self.good_style))
        
        story.append(Spacer(1, 20))
        
        # URL Details
        if 'url_details' in results:
            story.append(Paragraph("URL Technical Details", self.subtitle_style))
            url_details = results['url_details']
            
            detail_data = [
                ["Domain", url_details.get('domain', 'N/A')],
                ["Main Domain", url_details.get('main_domain', 'N/A')],
                ["TLD", url_details.get('tld', 'N/A')],
                ["HTTPS", "Yes" if url_details.get('https') else "No"],
                ["IP Address", url_details.get('ip_address', 'N/A')],
                ["Subdomain Count", str(url_details.get('subdomain_count', 0))],
            ]
            
            detail_table = Table(detail_data, colWidths=[150, 300])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(detail_table)
            story.append(Spacer(1, 20))
        
        # Threat Intelligence
        if results.get('phishing_intelligence_match') or results.get('abused_infrastructure'):
            story.append(Paragraph("Threat Intelligence", self.subtitle_style))
            
            if results.get('phishing_intelligence_match'):
                intel_info = results.get('intel_info', {})
                story.append(Paragraph("🚨 Phishing Database Match", self.highlight_style))
                
                intel_data = []
                if intel_info.get('match_type') == 'exact':
                    intel_data.append(["Match Type", "Exact Subdomain Match"])
                    intel_data.append(["Subdomain", intel_info.get('subdomain', 'N/A')])
                    intel_data.append(["Source", intel_info.get('source', 'N/A')])
                    intel_data.append(["Detection Count", str(intel_info.get('detection_count', 0))])
                else:
                    intel_data.append(["Match Type", "Domain-level Match"])
                    intel_data.append(["Domain", intel_info.get('domain', 'N/A')])
                    intel_data.append(["Sources", ', '.join(intel_info.get('sources', ['N/A']))])
                    intel_data.append(["Total Detections", str(intel_info.get('detection_count', 0))])
                
                intel_table = Table(intel_data, colWidths=[150, 300])
                intel_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fdf2f2')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e74c3c')),
                ]))
                story.append(intel_table)
                story.append(Spacer(1, 10))
            
            if results.get('abused_infrastructure'):
                abuse_info = results.get('abuse_info', {})
                story.append(Paragraph("⚠️ Abused Infrastructure Detected", self.warning_style))
                
                abuse_data = [
                    ["Category", abuse_info.get('category', 'N/A')],
                    ["Risk Score", str(abuse_info.get('risk_score', 0))],
                    ["Description", abuse_info.get('description', 'N/A')],
                ]
                
                abuse_table = Table(abuse_data, colWidths=[150, 300])
                abuse_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f39c12')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fef9e7')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#f39c12')),
                ]))
                story.append(abuse_table)
        
        # IP Reputation (if available)
        if results.get('ip_reputation'):
            story.append(Spacer(1, 20))
            story.append(Paragraph("IP Reputation Analysis", self.subtitle_style))
            
            ip_reputation = results['ip_reputation']
            ip_data = [
                ["IP Address", ip_reputation.get('ip', 'N/A')],
                ["Reputation Score", f"{ip_reputation.get('score', 0)}/100"],
                ["Threat Level", ip_reputation.get('threat_level', 'N/A').upper()],
                ["Blacklisted", "Yes" if ip_reputation.get('is_blacklisted') else "No"],
                ["Sources Checked", ', '.join(ip_reputation.get('sources_checked', []))],
            ]
            
            ip_color = colors.HexColor('#e74c3c') if ip_reputation.get('score', 0) > 60 else colors.HexColor('#f39c12')
            ip_table = Table(ip_data, colWidths=[150, 300])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), ip_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ]))
            story.append(ip_table)
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.subtitle_style))
        
        risk_score = results.get('risk_score', 0)
        if risk_score <= 30:
            recs = [
                "The URL appears to be safe for normal browsing.",
                "Continue with standard security practices.",
                "Verify the website's SSL/TLS certificate if entering sensitive information.",
                "Keep your browser and security software up to date.",
            ]
        elif risk_score <= 60:
            recs = [
                "Exercise caution when visiting this website.",
                "Do not enter passwords or sensitive information.",
                "Verify the website's legitimacy through official channels.",
                "Check for HTTPS and valid SSL certificate.",
                "Consider using a virtual machine or sandbox for testing.",
            ]
        else:
            recs = [
                "DO NOT VISIT this website under any circumstances.",
                "DO NOT enter any personal or financial information.",
                "If already visited, change any passwords you may have entered.",
                "Run a full antivirus/malware scan on your system.",
                "Report this website to your IT security team.",
                "Consider blocking this domain at network/firewall level.",
            ]
        
        for rec in recs:
            story.append(Paragraph(f"• {rec}", self.normal_style))
        
        # Footer note
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "This report was generated automatically by MdhalaScan . "
            "For security investigations only. Not a guarantee of complete safety.",
            ParagraphStyle(
                'FooterNote',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#7f8c8d'),
                alignment=1
            )
        ))
        
        # Build PDF
        doc.build(story, onFirstPage=lambda canvas, doc: self._create_header_footer(canvas, doc, "URL Scan"),
                  onLaterPages=lambda canvas, doc: self._create_header_footer(canvas, doc, "URL Scan"))
        
        return filepath
    
    def generate_email_report(self, results: Dict, headers: str, body: str) -> str:
        """Generate PDF report for email scan"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results, 'email')
        
        # Create filename - FIXED: Use email_scan instead of url_scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"email_scan_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Title - FIXED: Email Analysis Report
        story.append(Paragraph("MdhalaScan Security Scan Report", self.title_style))
        story.append(Paragraph("Email Analysis Report", self.subtitle_style))
        story.append(Spacer(1, 20))
        
        # Risk Meter
        risk_score = results.get('risk_score', 0)
        story.append(self._create_risk_meter(risk_score))
        story.append(Spacer(1, 30))
        
        # Summary Table - FIXED: Email Analysis
        results['scan_type'] = 'Email Analysis'
        story.append(self._create_summary_table(results, 'Email Analysis'))
        story.append(Spacer(1, 30))
        
        # Email Headers
        if headers:
            story.append(Paragraph("Email Headers Analysis", self.subtitle_style))
            
            # Truncate long headers for display
            display_headers = headers
            if len(headers) > 2000:
                display_headers = headers[:2000] + "\n\n[...truncated...]"
            
            story.append(Paragraph(
                display_headers,
                ParagraphStyle(
                    'HeadersStyle',
                    parent=self.styles['Normal'],
                    fontSize=8,
                    fontName='Courier',
                    textColor=colors.HexColor('#2c3e50'),
                    backColor=colors.HexColor('#f8f9fa'),
                    borderPadding=10,
                    borderColor=colors.lightgrey,
                    borderWidth=1
                )
            ))
            story.append(Spacer(1, 20))
        
        # Email Body
        if body:
            story.append(Paragraph("Email Body Content", self.subtitle_style))
            
            # Truncate very long bodies
            display_body = body
            if len(body) > 5000:
                display_body = body[:5000] + "\n\n[...content truncated...]"
            
            story.append(Paragraph(
                display_body,
                ParagraphStyle(
                    'BodyStyle',
                    parent=self.styles['Normal'],
                    fontSize=9,
                    textColor=colors.HexColor('#2c3e50'),
                    backColor=colors.HexColor('#f8f9fa'),
                    borderPadding=10,
                    borderColor=colors.lightgrey,
                    borderWidth=1
                )
            ))
            story.append(Spacer(1, 20))
        
        # Findings
        story.append(Paragraph("Security Findings", self.subtitle_style))
        
        findings = results.get('findings', [])
        if findings:
            for finding in findings:
                if '❌' in finding or 'HIGH RISK' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.highlight_style))
                elif '⚠️' in finding or 'SUSPICIOUS' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.warning_style))
                elif '✓' in finding:
                    story.append(Paragraph(f"• {finding}", self.good_style))
                else:
                    story.append(Paragraph(f"• {finding}", self.normal_style))
        else:
            story.append(Paragraph("No significant findings detected.", self.good_style))
        
        # URL Analysis Results
        if results.get('url_scan_results'):
            story.append(Spacer(1, 20))
            story.append(Paragraph("Embedded URL Analysis", self.subtitle_style))
            
            url_results = results['url_scan_results']
            url_data = [
                ["Total URLs Detected", str(url_results.get('total_urls', 0))],
                ["URLs Scanned", str(url_results.get('scanned_urls', 0))],
                ["Safe URLs", str(url_results.get('safe_urls', 0))],
                ["Suspicious URLs", str(url_results.get('suspicious_urls', 0))],
                ["High-Risk URLs", str(url_results.get('high_risk_urls', 0))],
            ]
            
            url_table = Table(url_data, colWidths=[150, 100])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ]))
            story.append(url_table)
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.subtitle_style))
        
        if risk_score <= 30:
            recs = [
                "This email appears to be legitimate.",
                "Continue with normal caution when interacting with emails.",
                "Verify the sender's identity if you have any doubts.",
                "Be cautious of unexpected attachments even from known senders.",
            ]
        elif risk_score <= 60:
            recs = [
                "This email shows suspicious characteristics.",
                "Do not click any links in this email.",
                "Do not download or open any attachments.",
                "Verify the sender through alternative means (phone, official website).",
                "Mark as spam if received from unknown sender.",
                "Delete the email if no legitimate reason to keep it.",
            ]
        else:
            recs = [
                "THIS IS A HIGH-RISK PHISHING EMAIL.",
                "DELETE THIS EMAIL IMMEDIATELY.",
                "DO NOT REPLY TO THE SENDER.",
                "DO NOT CLICK ANY LINKS OR BUTTONS.",
                "DO NOT DOWNLOAD ANY ATTACHMENTS.",
                "Report this email to your IT security team immediately.",
                "If you clicked any links, run a full system scan.",
                "Monitor your accounts for suspicious activity.",
            ]
        
        for rec in recs:
            story.append(Paragraph(f"• {rec}", self.normal_style))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "⚠️ WARNING: This email contains potentially sensitive information. "
            "Handle this report with appropriate security measures.",
            ParagraphStyle(
                'WarningStyle',
                parent=self.styles['Normal'],
                fontSize=9,
                textColor=colors.HexColor('#e74c3c'),
                alignment=1
            )
        ))
        
        # Build PDF - FIXED: Use Email Scan in header
        doc.build(story, onFirstPage=lambda canvas, doc: self._create_header_footer(canvas, doc, "Email Scan"),
                  onLaterPages=lambda canvas, doc: self._create_header_footer(canvas, doc, "Email Scan"))
        
        return filepath
    
    def generate_ip_report(self, results: Dict) -> str:
        """Generate PDF report for IP reputation check"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results, 'ip')
        
        # Create filename - FIXED: Use ip_check instead of url_scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_address = results.get('ip_address', 'unknown').replace('.', '_')
        filename = f"ip_check_{ip_address}_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Title - FIXED: IP Reputation Report
        story.append(Paragraph("MdhalaScan Security Scan Report", self.title_style))
        story.append(Paragraph("IP Reputation Analysis Report", self.subtitle_style))
        story.append(Spacer(1, 20))
        
        # Risk Meter
        risk_score = results.get('risk_score', 0)
        story.append(self._create_risk_meter(risk_score))
        story.append(Spacer(1, 30))
        
        # Summary Table - FIXED: IP Reputation Analysis
        results['scan_type'] = 'IP Reputation Analysis'
        story.append(self._create_summary_table(results, 'IP Reputation Analysis'))
        story.append(Spacer(1, 30))
        
        # IP Details
        if results.get('ip_reputation'):
            story.append(Paragraph("IP Reputation Details", self.subtitle_style))
            
            ip_reputation = results['ip_reputation']
            
            # Basic IP info
            ip_data = [
                ["IP Address", ip_reputation.get('ip', 'N/A')],
                ["Reputation Score", f"{ip_reputation.get('score', 0)}/100"],
                ["Threat Level", ip_reputation.get('threat_level', 'N/A').upper()],
                ["Blacklisted", "Yes" if ip_reputation.get('is_blacklisted') else "No"],
                ["Last Checked", ip_reputation.get('last_checked', 'N/A')],
            ]
            
            ip_table = Table(ip_data, colWidths=[150, 300])
            ip_color = colors.HexColor('#e74c3c') if ip_reputation.get('score', 0) > 60 else colors.HexColor('#f39c12')
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), ip_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(ip_table)
            story.append(Spacer(1, 20))
            
            # Sources checked
            if ip_reputation.get('sources_checked'):
                story.append(Paragraph("Threat Intelligence Sources", self.subtitle_style))
                sources = ip_reputation['sources_checked']
                sources_text = ', '.join(sources)
                story.append(Paragraph(f"Sources checked: {sources_text}", self.normal_style))
                story.append(Spacer(1, 10))
            
            # Blocklist details
            if ip_reputation.get('is_blacklisted') and ip_reputation.get('details', {}).get('blocklists'):
                story.append(Paragraph("Blocklist Details", self.subtitle_style))
                blocklists = ip_reputation['details']['blocklists']
                for blocklist in blocklists[:5]:  # Show first 5 blocklists
                    story.append(Paragraph(f"• {blocklist}", self.highlight_style))
            
            # Additional details
            if ip_reputation.get('details'):
                story.append(Spacer(1, 20))
                story.append(Paragraph("Additional Information", self.subtitle_style))
                
                details = ip_reputation['details']
                for key, value in details.items():
                    if key not in ['blocklists']:  # Skip blocklists as they're handled above
                        if isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                story.append(Paragraph(f"{key}.{subkey}: {subvalue}", self.normal_style))
                        else:
                            story.append(Paragraph(f"{key}: {value}", self.normal_style))
        
        # Findings
        story.append(Spacer(1, 20))
        story.append(Paragraph("Security Findings", self.subtitle_style))
        
        findings = results.get('findings', [])
        if findings:
            for finding in findings:
                if '❌' in finding or 'HIGH RISK' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.highlight_style))
                elif '⚠️' in finding or 'SUSPICIOUS' in finding.upper():
                    story.append(Paragraph(f"• {finding}", self.warning_style))
                elif '✓' in finding:
                    story.append(Paragraph(f"• {finding}", self.good_style))
                else:
                    story.append(Paragraph(f"• {finding}", self.normal_style))
        else:
            story.append(Paragraph("No significant findings detected.", self.good_style))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.subtitle_style))
        
        risk_score = results.get('risk_score', 0)
        if risk_score <= 30:
            recs = [
                "This IP address appears to be safe.",
                "No immediate action required.",
                "Continue with normal security monitoring.",
                "Consider whitelisting if this is your own infrastructure.",
            ]
        elif risk_score <= 60:
            recs = [
                "This IP address shows suspicious characteristics.",
                "Monitor traffic from this IP address.",
                "Consider implementing additional firewall rules.",
                "Review logs for any suspicious activity from this IP.",
                "Do not whitelist without further investigation.",
            ]
        else:
            recs = [
                "THIS IP ADDRESS IS HIGH RISK.",
                "Block this IP address at your firewall immediately.",
                "Review all systems for potential compromise.",
                "Check for any unauthorized access from this IP.",
                "Report this IP to your IT security team.",
                "Consider reporting to abuse contact for the IP's ISP.",
            ]
        
        for rec in recs:
            story.append(Paragraph(f"• {rec}", self.normal_style))
        
        # Footer note
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "This report was generated automatically by MdhalaScan . "
            "IP reputation data is sourced from public threat intelligence feeds. "
            "For security investigations only.",
            ParagraphStyle(
                'FooterNote',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#7f8c8d'),
                alignment=1
            )
        ))
        
        # Build PDF - FIXED: Use IP Reputation Scan in header
        doc.build(story, onFirstPage=lambda canvas, doc: self._create_header_footer(canvas, doc, "IP Reputation Scan"),
                  onLaterPages=lambda canvas, doc: self._create_header_footer(canvas, doc, "IP Reputation Scan"))
        
        return filepath
    
    def generate_file_report(self, results: Dict) -> str:
        """Generate PDF report for file scan"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results, 'file')
        
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = results.get('filename', 'file').replace(' ', '_').replace('.', '_')[:50]
        filename = f"file_scan_{safe_name}_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("MdhalaScan Security Scan Report", self.title_style))
        story.append(Paragraph("File Malware Analysis Report", self.subtitle_style))
        story.append(Spacer(1, 20))
        
        # Risk Meter
        risk_score = results.get('risk_score', 0)
        story.append(self._create_risk_meter(risk_score))
        story.append(Spacer(1, 30))
        
        # Summary Table
        results['scan_type'] = 'File Malware Analysis'
        story.append(self._create_summary_table(results, 'File Analysis'))
        story.append(Spacer(1, 30))
        
        # File Information
        story.append(Paragraph("File Information", self.subtitle_style))
        
        file_info = [
            ["Filename", results.get('filename', 'N/A')],
            ["File Path", results.get('file_path', 'N/A')],
            ["File Size", f"{results.get('file_size', 0):,} bytes"],
        ]
        
        if results.get('hashes'):
            hashes = results['hashes']
            file_info.append(["MD5 Hash", hashes.get('md5', 'N/A')])
            file_info.append(["SHA256 Hash", hashes.get('sha256', 'N/A')])
        
        if results.get('file_type'):
            ftype = results['file_type']
            file_info.append(["Detected Type", ftype.get('detected_type', 'Unknown')])
            file_info.append(["File Extension", f".{ftype.get('extension', 'N/A')}"])
            if ftype.get('signature_description'):
                file_info.append(["Signature", ftype.get('signature_description')])
        
        file_table = Table(file_info, colWidths=[150, 300])
        file_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        story.append(file_table)
        story.append(Spacer(1, 20))
        
        # Hash Intelligence
        if results.get('hash_match'):
            story.append(Paragraph("Threat Intelligence", self.subtitle_style))
            story.append(Paragraph("🚨 Known Malware Hash Match", self.highlight_style))
            
            intel_info = results.get('intel_info', {})
            intel_data = [
                ["Hash", intel_info.get('hash', 'N/A')],
                ["Threat Name", intel_info.get('threat_name', 'Unknown')],
                ["Source", intel_info.get('source', 'Unknown')],
                ["First Seen", intel_info.get('first_seen', 'Unknown')],
                ["Risk Score", str(intel_info.get('risk_score', 0)) + "/100"],
            ]
            
            intel_table = Table(intel_data, colWidths=[150, 300])
            intel_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fdf2f2')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e74c3c')),
            ]))
            story.append(intel_table)
            story.append(Spacer(1, 20))
        
        # External Reputation
        if results.get('external_reputation'):
            ext_rep = results['external_reputation']
            
            if ext_rep.get('malwarebazaar', {}).get('found') or ext_rep.get('threatfox', {}).get('found'):
                story.append(Paragraph("External Threat Intelligence", self.subtitle_style))
                
                if ext_rep['malwarebazaar']['found']:
                    story.append(Paragraph("❌ Found in MalwareBazaar Database", self.highlight_style))
                
                if ext_rep['threatfox']['found']:
                    story.append(Paragraph("❌ Found in ThreatFox Database", self.highlight_style))
        
        # Findings
        story.append(Paragraph("Security Findings", self.subtitle_style))
        
        findings = results.get('findings', [])
        if findings:
            for finding in findings:
                if '❌' in finding:
                    story.append(Paragraph(f"• {finding}", self.highlight_style))
                elif '⚠️' in finding:
                    story.append(Paragraph(f"• {finding}", self.warning_style))
                else:
                    story.append(Paragraph(f"• {finding}", self.normal_style))
        else:
            story.append(Paragraph("• No significant threats detected", self.good_style))
        
        # Analysis Details
        if results.get('analysis_results'):
            story.append(Spacer(1, 20))
            story.append(Paragraph("Technical Analysis", self.subtitle_style))
            
            analysis = results['analysis_results']
            
            if 'entropy' in analysis:
                entropy = analysis['entropy']
                entropy_color = colors.HexColor('#e74c3c') if entropy > 7.5 else colors.HexColor('#f39c12') if entropy > 6.5 else colors.HexColor('#27ae60')
                story.append(Paragraph(f"Entropy: {entropy:.2f} (measure of randomness)", self.normal_style))
            
            if 'yara_matches' in results and results['yara_matches']:
                story.append(Paragraph("YARA Rule Matches:", self.warning_style))
                for match in results['yara_matches']:
                    story.append(Paragraph(f"  • {match.get('rule', 'Unknown')}", self.normal_style))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.subtitle_style))
        
        if risk_score <= 30:
            recs = [
                "The file appears to be safe for normal use.",
                "Continue with standard security practices.",
                "Keep your antivirus software up to date.",
            ]
        elif risk_score <= 60:
            recs = [
                "Exercise caution with this file.",
                "Scan the file with your antivirus software before opening.",
                "Do not run the file with administrator privileges.",
                "Consider opening in a sandboxed environment if available.",
            ]
        else:
            recs = [
                "DO NOT OPEN THIS FILE UNDER ANY CIRCUMSTANCES.",
                "Delete the file immediately from your system.",
                "Run a full system antivirus scan.",
                "If already opened, monitor your system for suspicious activity.",
                "Report this file to your IT security team.",
            ]
        
        for rec in recs:
            story.append(Paragraph(f"• {rec}", self.normal_style))
        
        # Footer note
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "This report was generated automatically by MdhalaScan . "
            "File analysis includes static analysis and hash reputation checking. "
            "Not a guarantee of complete safety.",
            ParagraphStyle(
                'FooterNote',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#7f8c8d'),
                alignment=1
            )
        ))
        
        # Build PDF
        doc.build(story, onFirstPage=lambda canvas, doc: self._create_header_footer(canvas, doc, "File Scan"),
                onLaterPages=lambda canvas, doc: self._create_header_footer(canvas, doc, "File Scan"))
        
        return filepath
    
    def generate_directory_report(self, results: Dict) -> str:
        """Generate PDF report for directory scan"""
        if not REPORTLAB_AVAILABLE:
            return self._generate_text_report(results, 'directory')
        
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dir_name = os.path.basename(results.get('directory', 'directory')).replace(' ', '_')[:50]
        filename = f"directory_scan_{dir_name}_{timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("MdhalaScan Security Scan Report", self.title_style))
        story.append(Paragraph("Directory Malware Scan Report", self.subtitle_style))
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Scan Summary", self.subtitle_style))
        
        summary_data = [
            ["Directory Scanned", results.get('directory', 'N/A')],
            ["Scan Time", results.get('scan_time', 'N/A')],
            ["Total Files Found", str(results.get('total_files', 0))],
            ["Files Scanned", str(results.get('scanned_files', 0))],
            ["Safe Files", str(results.get('safe_files', 0))],
            ["Suspicious Files", str(results.get('suspicious_files', 0))],
            ["Malicious Files", str(results.get('malicious_files', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[150, 300])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Show malicious files
        malicious_files = [f for f in results.get('file_results', []) if f.get('risk_score', 0) > 60]
        if malicious_files:
            story.append(Paragraph("🚨 Malicious Files Detected", self.highlight_style))
            
            malicious_data = [["Filename", "Risk Score", "Threat Name"]]
            for file_result in malicious_files[:10]:  # Show first 10
                malicious_data.append([
                    file_result.get('filename', 'Unknown'),
                    str(file_result.get('risk_score', 0)) + "%",
                    file_result.get('threat_name', 'Unknown')
                ])
            
            malicious_table = Table(malicious_data, colWidths=[200, 80, 200])
            malicious_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fdf2f2')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e74c3c')),
            ]))
            story.append(malicious_table)
            story.append(Spacer(1, 20))
        
        # Show suspicious files
        suspicious_files = [f for f in results.get('file_results', []) if 30 < f.get('risk_score', 0) <= 60]
        if suspicious_files:
            story.append(Paragraph("⚠️ Suspicious Files", self.warning_style))
            
            suspicious_data = [["Filename", "Risk Score", "Findings"]]
            for file_result in suspicious_files[:10]:  # Show first 10
                findings = file_result.get('findings', [])
                first_finding = findings[0] if findings else 'None'
                suspicious_data.append([
                    file_result.get('filename', 'Unknown'),
                    str(file_result.get('risk_score', 0)) + "%",
                    first_finding[:50] + "..." if len(first_finding) > 50 else first_finding
                ])
            
            suspicious_table = Table(suspicious_data, colWidths=[200, 80, 220])
            suspicious_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f39c12')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fef9e7')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#f39c12')),
            ]))
            story.append(suspicious_table)
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.subtitle_style))
        
        malicious_count = results.get('malicious_files', 0)
        suspicious_count = results.get('suspicious_files', 0)
        
        if malicious_count == 0 and suspicious_count == 0:
            recs = [
                "The directory appears to be clean.",
                "No immediate action required.",
                "Continue with normal security monitoring.",
            ]
        elif malicious_count == 0:
            recs = [
                "Suspicious files found in directory.",
                "Review suspicious files before opening.",
                "Consider scanning suspicious files with antivirus software.",
                "Delete any unnecessary suspicious files.",
            ]
        else:
            recs = [
                "MALICIOUS FILES DETECTED IN DIRECTORY!",
                "1. Isolate the affected system if possible.",
                "2. Delete all malicious files immediately.",
                "3. Run a full system antivirus scan.",
                "4. Check for signs of system compromise.",
                "5. Report the incident to IT security.",
                "6. Monitor for unusual network activity.",
            ]
        
        for rec in recs:
            if rec.startswith("MALICIOUS") or rec.startswith("1."):
                story.append(Paragraph(f"• {rec}", self.highlight_style))
            else:
                story.append(Paragraph(f"• {rec}", self.normal_style))
        
        # Footer note
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "This report was generated automatically by MdhalaScan  "
            "Directory scans provide an overview of file security in the scanned location. "
            "Individual files may require deeper analysis.",
            ParagraphStyle(
                'FooterNote',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#7f8c8d'),
                alignment=1
            )
        ))
        
        # Build PDF
        doc.build(story, onFirstPage=lambda canvas, doc: self._create_header_footer(canvas, doc, "Directory Scan"),
                  onLaterPages=lambda canvas, doc: self._create_header_footer(canvas, doc, "Directory Scan"))
        
        return filepath
    
    def _generate_text_report(self, results: Dict, scan_type: str) -> str:
        """Fallback text report if PDF library not available"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_type}_scan_{timestamp}.txt"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("MDHALASCAN SECURITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Type: {scan_type.upper()} Scan\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner Version: 1.8\n\n")
            
            if scan_type == 'url':
                f.write(f"Target URL: {results.get('url', 'N/A')}\n")
            elif scan_type == 'email':
                f.write("Email Analysis Report\n")
            elif scan_type == 'ip':
                f.write(f"Target IP: {results.get('ip_address', 'N/A')}\n")
            elif scan_type == 'file':
                f.write(f"Target File: {results.get('filename', 'N/A')}\n")
            elif scan_type == 'directory':
                f.write(f"Target Directory: {results.get('directory', 'N/A')}\n")
            
            f.write(f"\nRisk Score: {results.get('risk_score', 0)}/100\n")
            f.write(f"Recommendation: {results.get('recommendation', 'N/A')}\n\n")
            
            f.write("FINDINGS:\n")
            f.write("-" * 80 + "\n")
            for finding in results.get('findings', []):
                f.write(f"{finding}\n")
        
        return filepath