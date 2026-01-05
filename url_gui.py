#!/usr/bin/env python3
"""
URLGuard GUI - Graphical Malicious URL Checker
Tkinter based GUI for Kali Linux
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from urllib.parse import urlparse
import re
import socket
import requests
from datetime import datetime
import os
import sys

class URLGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 URLGuard - AI Malicious URL Detector")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2c3e50')
        
        # Queue for thread-safe GUI updates
        self.queue = queue.Queue()
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        
        # Check for queue updates
        self.root.after(100, self.process_queue)
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        self.colors = {
            'bg': '#2c3e50',
            'fg': '#ecf0f1',
            'button': '#3498db',
            'button_hover': '#2980b9',
            'danger': '#e74c3c',
            'success': '#27ae60',
            'warning': '#f39c12',
            'card': '#34495e'
        }
        
        # Configure styles
        style.configure('Title.TLabel', 
                       background=self.colors['bg'],
                       foreground=self.colors['fg'],
                       font=('Helvetica', 24, 'bold'))
        
        style.configure('Card.TFrame',
                       background=self.colors['card'],
                       relief='raised',
                       borderwidth=2)
        
        style.configure('Scan.TButton',
                       background=self.colors['button'],
                       foreground='white',
                       font=('Helvetica', 12, 'bold'),
                       padding=10)
        
        style.map('Scan.TButton',
                 background=[('active', self.colors['button_hover'])])
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Title Frame
        title_frame = ttk.Frame(self.root, style='Card.TFrame')
        title_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = ttk.Label(title_frame, 
                               text="🔒 URLGuard - AI Malicious URL Detector",
                               style='Title.TLabel')
        title_label.pack(pady=20)
        
        subtitle_label = ttk.Label(title_frame,
                                  text="Cybersecurity Project | Kali Linux",
                                  font=('Helvetica', 12),
                                  background=self.colors['card'],
                                  foreground='#bdc3c7')
        subtitle_label.pack()
        
        # Main Container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left Panel - Input
        left_panel = ttk.Frame(main_container, style='Card.TFrame')
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # URL Input Section
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(input_frame, 
                 text="Enter URL to Scan:",
                 font=('Helvetica', 14, 'bold'),
                 background=self.colors['card'],
                 foreground=self.colors['fg']).pack(anchor='w', pady=(0, 10))
        
        self.url_entry = ttk.Entry(input_frame, font=('Helvetica', 12))
        self.url_entry.pack(fill='x', pady=(0, 10))
        self.url_entry.insert(0, "https://")
        self.url_entry.bind('<Return>', lambda e: self.scan_url())
        
        # Button Frame
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill='x', pady=10)
        
        scan_btn = ttk.Button(button_frame,
                             text="🔍 Scan URL",
                             style='Scan.TButton',
                             command=self.scan_url)
        scan_btn.pack(side='left', padx=(0, 10))
        
        batch_btn = ttk.Button(button_frame,
                              text="📁 Batch Scan",
                              command=self.batch_scan)
        batch_btn.pack(side='left')
        
        # Example URLs
        example_frame = ttk.Frame(left_panel, style='Card.TFrame')
        example_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(example_frame,
                 text="Try these examples:",
                 font=('Helvetica', 11, 'bold'),
                 background=self.colors['card'],
                 foreground=self.colors['fg']).pack(anchor='w', pady=(10, 5))
        
        examples = [
            "https://www.google.com",
            "http://free-gift-card.xyz/login.php",
            "https://bit.ly/3x7y8z9",
            "http://192.168.1.100/login"
        ]
        
        for example in examples:
            example_btn = ttk.Button(example_frame,
                                    text=example,
                                    command=lambda e=example: self.set_example(e))
            example_btn.pack(fill='x', pady=2)
        
        # Progress Bar
        self.progress = ttk.Progressbar(left_panel, mode='indeterminate')
        self.progress.pack(fill='x', padx=20, pady=10)
        
        # Right Panel - Results
        right_panel = ttk.Frame(main_container, style='Card.TFrame')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Results Display
        results_frame = ttk.Frame(right_panel)
        results_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        ttk.Label(results_frame,
                 text="Scan Results:",
                 font=('Helvetica', 14, 'bold'),
                 background=self.colors['card'],
                 foreground=self.colors['fg']).pack(anchor='w', pady=(0, 10))
        
        # Result Status
        self.result_status = ttk.Label(results_frame,
                                      text="Ready to scan...",
                                      font=('Helvetica', 16),
                                      background=self.colors['card'])
        self.result_status.pack(anchor='w', pady=(0, 10))
        
        # Score Label
        self.score_label = ttk.Label(results_frame,
                                    text="Risk Score: 0/100",
                                    font=('Helvetica', 12),
                                    background=self.colors['card'])
        self.score_label.pack(anchor='w', pady=(0, 10))
        
        # Issues List
        ttk.Label(results_frame,
                 text="Issues Found:",
                 font=('Helvetica', 12, 'bold'),
                 background=self.colors['card'],
                 foreground=self.colors['fg']).pack(anchor='w', pady=(10, 5))
        
        self.issues_text = scrolledtext.ScrolledText(results_frame,
                                                    height=8,
                                                    font=('Courier', 10),
                                                    bg='#1a252f',
                                                    fg='white',
                                                    insertbackground='white')
        self.issues_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Details Section
        details_frame = ttk.Frame(results_frame)
        details_frame.pack(fill='x', pady=10)
        
        ttk.Label(details_frame,
                 text="Scan Details:",
                 font=('Helvetica', 12, 'bold'),
                 background=self.colors['card'],
                 foreground=self.colors['fg']).pack(anchor='w')
        
        self.details_text = scrolledtext.ScrolledText(details_frame,
                                                     height=6,
                                                     font=('Courier', 9),
                                                     bg='#1a252f',
                                                     fg='#bdc3c7')
        self.details_text.pack(fill='x')
        
        # Bottom Status Bar
        status_bar = ttk.Frame(self.root, style='Card.TFrame')
        status_bar.pack(side='bottom', fill='x', padx=20, pady=10)
        
        self.status_label = ttk.Label(status_bar,
                                     text="Ready",
                                     font=('Helvetica', 10),
                                     background=self.colors['card'],
                                     foreground='#95a5a6')
        self.status_label.pack(side='left')
        
        # Log button
        ttk.Button(status_bar,
                  text="View Log",
                  command=self.view_log).pack(side='right')
    
    def set_example(self, url):
        """Set example URL in entry"""
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)
    
    def scan_url(self):
        """Start URL scanning in separate thread"""
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showwarning("Input Error", "Please enter a URL to scan")
            return
        
        # Disable button and show progress
        self.progress.start()
        self.result_status.config(text="Scanning...")
        self.status_label.config(text=f"Scanning: {url[:50]}...")
        
        # Clear previous results
        self.issues_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        
        # Start scan in separate thread
        thread = threading.Thread(target=self._scan_thread, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _scan_thread(self, url):
        """Thread function for scanning"""
        try:
            results = self.perform_scan(url)
            self.queue.put(('results', results))
        except Exception as e:
            self.queue.put(('error', str(e)))
    
    def perform_scan(self, url):
        """Perform actual URL scanning"""
        results = {
            'url': url,
            'status': 'SAFE',
            'score': 0,
            'issues': [],
            'details': {}
        }
        
        # 1. Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            results['issues'].append("Invalid URL format")
            results['score'] = 100
            return results
        
        # 2. Check for IP address
        try:
            socket.inet_aton(domain.replace('www.', ''))
            results['issues'].append("Uses IP address instead of domain")
            results['score'] += 25
        except:
            pass
        
        # 3. Check URL length
        if len(url) > 100:
            results['issues'].append(f"URL too long ({len(url)} chars)")
            results['score'] += 10
        
        # 4. Check for suspicious patterns
        suspicious_patterns = [
            ('@', "Contains @ symbol (obfuscation)"),
            ('//', "Double slash in path"),
            ('bit.ly|tinyurl|goo.gl', "URL shortening service"),
            ('login|signin|verify|secure|account', "Suspicious keywords"),
            (r'\d+\.\d+\.\d+\.\d+', "Contains IP pattern"),
        ]
        
        for pattern, message in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                results['issues'].append(message)
                results['score'] += 15
        
        # 5. Try to connect
        try:
            headers = {'User-Agent': 'URLGuard-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            results['details']['Status Code'] = response.status_code
            results['details']['Response Time'] = f"{response.elapsed.total_seconds():.2f}s"
            results['details']['Content Size'] = f"{len(response.content)} bytes"
            
            if response.status_code != 200:
                results['issues'].append(f"Non-200 status: {response.status_code}")
                results['score'] += 10
            
            # Check for common phishing page indicators
            content_lower = response.text.lower()
            phishing_indicators = ['password', 'login', 'username', 'bank', 'verify']
            found = [ind for ind in phishing_indicators if ind in content_lower]
            
            if len(found) > 3:
                results['issues'].append(f"Phishing page indicators: {', '.join(found[:3])}")
                results['score'] += 20
            
        except requests.exceptions.SSLError:
            results['issues'].append("SSL Certificate error")
            results['score'] += 15
        except requests.exceptions.RequestException as e:
            results['issues'].append(f"Connection failed: {str(e)}")
            results['score'] += 10
        
        # 6. Final scoring
        if results['score'] >= 60:
            results['status'] = "🚨 HIGH RISK"
            color = "#e74c3c"
        elif results['score'] >= 30:
            results['status'] = "⚠️ MEDIUM RISK"
            color = "#f39c12"
        else:
            results['status'] = "✅ SAFE"
            color = "#27ae60"
        
        results['color'] = color
        results['details']['Final Score'] = results['score']
        
        # Log the scan
        self.log_scan(results)
        
        return results
    
    def log_scan(self, results):
        """Log scan results to file"""
        log_file = os.path.expanduser("~/urlguard_scans.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(log_file, 'a') as f:
            f.write(f"\n[{timestamp}]\n")
            f.write(f"URL: {results['url']}\n")
            f.write(f"Status: {results['status']}\n")
            f.write(f"Score: {results['score']}\n")
            f.write(f"Issues: {len(results['issues'])}\n")
            for issue in results['issues']:
                f.write(f"  - {issue}\n")
            f.write("-"*40 + "\n")
    
    def batch_scan(self):
        """Scan multiple URLs from file"""
        file_path = filedialog.askopenfilename(
            title="Select file with URLs",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                messagebox.showinfo("Empty File", "The selected file is empty")
                return
            
            # Create batch scan window
            batch_window = tk.Toplevel(self.root)
            batch_window.title(f"Batch Scan - {len(urls)} URLs")
            batch_window.geometry("800x600")
            
            # Results text area
            text_area = scrolledtext.ScrolledText(batch_window, font=('Courier', 10))
            text_area.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Progress bar
            progress = ttk.Progressbar(batch_window, maximum=len(urls))
            progress.pack(fill='x', padx=10, pady=5)
            
            # Start scanning in thread
            def scan_all():
                results_summary = []
                for i, url in enumerate(urls):
                    try:
                        result = self.perform_scan(url)
                        line = f"{'🚨' if result['score'] > 50 else '✅'} {url[:60]:60} Score: {result['score']:3d} - {result['status']}"
                        text_area.insert(tk.END, line + '\n')
                        text_area.see(tk.END)
                        results_summary.append(result)
                    except Exception as e:
                        text_area.insert(tk.END, f"❌ {url[:60]:60} Error: {str(e)[:30]}\n")
                    
                    progress['value'] = i + 1
                    batch_window.update()
                
                # Show summary
                high_risk = sum(1 for r in results_summary if r.get('score', 0) > 50)
                text_area.insert(tk.END, "\n" + "="*70 + "\n")
                text_area.insert(tk.END, f"SUMMARY: {len(urls)} URLs scanned\n")
                text_area.insert(tk.END, f"High Risk: {high_risk}\n")
                text_area.insert(tk.END, f"Safe: {len(urls) - high_risk}\n")
            
            thread = threading.Thread(target=scan_all)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")
    
    def view_log(self):
        """View scan log file"""
        log_file = os.path.expanduser("~/urlguard_scans.log")
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                content = f.read()
            
            # Create log viewer window
            log_window = tk.Toplevel(self.root)
            log_window.title("Scan Log")
            log_window.geometry("900x600")
            
            text_area = scrolledtext.ScrolledText(log_window, font=('Courier', 10))
            text_area.pack(fill='both', expand=True, padx=10, pady=10)
            text_area.insert(tk.END, content)
            text_area.config(state='disabled')
            
            # Add clear button
            def clear_log():
                if messagebox.askyesno("Clear Log", "Delete all log entries?"):
                    open(log_file, 'w').close()
                    text_area.delete(1.0, tk.END)
                    messagebox.showinfo("Log Cleared", "Scan log has been cleared")
            
            ttk.Button(log_window, text="Clear Log", command=clear_log).pack(pady=10)
        else:
            messagebox.showinfo("No Log", "No scan log found yet")
    
    def process_queue(self):
        """Process messages from queue"""
        try:
            while True:
                msg_type, data = self.queue.get_nowait()
                
                if msg_type == 'results':
                    self.display_results(data)
                elif msg_type == 'error':
                    messagebox.showerror("Scan Error", data)
                    self.progress.stop()
                    self.result_status.config(text="Scan Failed")
                
        except queue.Empty:
            pass
        
        self.root.after(100, self.process_queue)
    
    def display_results(self, results):
        """Display scan results in GUI"""
        # Stop progress bar
        self.progress.stop()
        
        # Update status
        self.result_status.config(text=results['status'], foreground=results['color'])
        self.score_label.config(text=f"Risk Score: {results['score']}/100")
        
        # Show issues
        self.issues_text.delete(1.0, tk.END)
        if results['issues']:
            for issue in results['issues']:
                self.issues_text.insert(tk.END, f"• {issue}\n")
        else:
            self.issues_text.insert(tk.END, "No issues found! ✅\n")
        
        # Show details
        self.details_text.delete(1.0, tk.END)
        for key, value in results['details'].items():
            self.details_text.insert(tk.END, f"{key}: {value}\n")
        
        # Update status bar
        self.status_label.config(text=f"Last scan: {results['url'][:40]}...")
        
        # Show warning if high risk
        if results['score'] > 50:
            messagebox.showwarning("High Risk URL", 
                                 f"This URL appears to be malicious!\n\n"
                                 f"Score: {results['score']}/100\n"
