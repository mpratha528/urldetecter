#!/usr/bin/env python3
"""
URLGuard - Terminal Malicious URL Checker
Kali Linux ke liye optimized
"""

import sys
import re
import socket
import requests
import urllib.parse
from datetime import datetime
import os

class URLScanner:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'bank', 'paypal', 
            'update', 'confirm', 'password', 'wallet', 'free', 'gift',
            'bonus', 'prize', 'win', 'click', 'download', 'install'
        ]
        
        self.short_domains = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'tiny.cc', 'shorte.st'
        ]
        
        self.blacklist_domains = [
            'malware.com', 'phishingsite.net', 'hackers.ru',
            'free-virus-download.com', 'cracked-software.xyz'
        ]
        
    def print_banner(self):
        print(r"""
╦ ╦╔═╗╦═╗╔═╗  ╔═╗╦ ╦╔═╗╦═╗╦ ╦╔╦╗
║║║║╣ ╠╦╝║╣   ╠═╝╚╦╝║ ║╠╦╝║ ║ ║ 
╚╩╝╚═╝╩╚═╚═╝  ╩   ╩ ╚═╝╩╚═╚═╝ ╩ 
        URL Security Scanner
        """)
    
    def check_url(self, url):
        """Main function to check URL"""
        results = {
            'url': url,
            'status': 'SAFE',
            'score': 0,
            'issues': [],
            'recommendation': 'Looks safe!',
            'details': {}
        }
        
        print(f"\n🔍 Scanning: {url}")
        print("="*50)
        
        # 1. Check if URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            results['url'] = url
        
        # 2. Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            results['details']['domain'] = domain
            results['details']['path'] = path
            
        except:
            results['issues'].append("❌ Invalid URL format")
            results['score'] += 30
            return results
        
        # 3. Check domain
        self.check_domain(domain, results)
        
        # 4. Check path and query
        self.check_path_query(path, query, results)
        
        # 5. Check for IP address
        self.check_ip_address(domain, results)
        
        # 6. Check URL length
        self.check_url_length(url, results)
        
        # 7. Check special characters
        self.check_special_chars(url, results)
        
        # 8. Try to connect (optional)
        self.check_connection(url, results)
        
        # 9. Calculate final score
        self.calculate_final_score(results)
        
        return results
    
    def check_domain(self, domain, results):
        """Check domain for suspicious patterns"""
        domain_lower = domain.lower()
        
        # Check for short domains
        for short in self.short_domains:
            if short in domain_lower:
                results['issues'].append(f"⚠️ Uses URL shortener: {short}")
                results['score'] += 20
        
        # Check blacklist
        for bad in self.blacklist_domains:
            if bad in domain_lower:
                results['issues'].append(f"🚨 Domain in blacklist: {bad}")
                results['score'] += 50
        
        # Check for IP in domain
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if re.search(ip_pattern, domain):
            results['issues'].append("⚠️ Contains IP address (not domain)")
            results['score'] += 15
    
    def check_path_query(self, path, query, results):
        """Check URL path and query string"""
        full_path = path + '?' + query if query else path
        
        # Check for suspicious keywords
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in full_path.lower():
                found_keywords.append(keyword)
        
        if found_keywords:
            results['issues'].append(f"⚠️ Suspicious keywords: {', '.join(found_keywords[:3])}")
            results['score'] += len(found_keywords) * 5
        
        # Check for too many parameters
        if query:
            params = query.split('&')
            if len(params) > 5:
                results['issues'].append(f"⚠️ Too many parameters ({len(params)})")
                results['score'] += 10
    
    def check_ip_address(self, domain, results):
        """Check if domain is IP address"""
        try:
            socket.inet_aton(domain.replace('www.', ''))
            results['issues'].append("🚨 Direct IP address access")
            results['score'] += 25
        except:
            pass
    
    def check_url_length(self, url, results):
        """Check URL length"""
        if len(url) > 75:
            results['issues'].append(f"⚠️ URL too long ({len(url)} chars)")
            results['score'] += 5
        results['details']['length'] = len(url)
    
    def check_special_chars(self, url, results):
        """Check for special characters"""
        special_chars = '@%&?=<>[]{}|\\^~`'
        count = sum(1 for char in url if char in special_chars)
        
        if count > 5:
            results['issues'].append(f"⚠️ Many special characters ({count})")
            results['score'] += count * 2
        
        results['details']['special_chars'] = count
    
    def check_connection(self, url, results):
        """Try to connect to URL"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (URLScanner Security Tool)'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            results['details']['status_code'] = response.status_code
            results['details']['response_time'] = response.elapsed.total_seconds()
            
            if response.status_code == 200:
                content_length = len(response.content)
                if content_length < 1000:
                    results['issues'].append("⚠️ Very small page (might be fake)")
                    results['score'] += 5
                
                results['details']['size'] = f"{content_length} bytes"
            
        except requests.exceptions.SSLError:
            results['issues'].append("⚠️ SSL Certificate issue")
            results['score'] += 10
        except requests.exceptions.RequestException as e:
            results['issues'].append(f"⚠️ Connection failed: {str(e)}")
            results['score'] += 5
        except:
            pass
    
    def calculate_final_score(self, results):
        """Calculate final risk score"""
        score = results['score']
        
        if score >= 50:
            results['status'] = "🚨 HIGH RISK"
            results['recommendation'] = "DO NOT VISIT! Likely malicious"
        elif score >= 30:
            results['status'] = "⚠️ MEDIUM RISK"
            results['recommendation'] = "Be cautious, suspicious elements found"
        elif score >= 15:
            results['status'] = "⚠️ LOW RISK"
            results['recommendation'] = "Some minor issues"
        else:
            results['status'] = "✅ SAFE"
            results['recommendation'] = "Looks safe to visit"
        
        results['details']['risk_score'] = score
    
    def display_results(self, results):
        """Display results in terminal"""
        print("\n" + "📊 SCAN RESULTS".center(50, "="))
        print(f"URL: {results['url']}")
        print(f"Status: {results['status']}")
        print(f"Risk Score: {results['details'].get('risk_score', 0)}/100")
        print(f"\nRecommendation: {results['recommendation']}")
        
        if results['issues']:
            print("\n⚠️ Issues Found:")
            for issue in results['issues']:
                print(f"  • {issue}")
        
        print("\n📈 Details:")
        for key, value in results['details'].items():
            if key != 'risk_score':
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print("\n" + "="*50)
        
        # Save to log file
        self.save_log(results)
    
    def save_log(self, results):
        """Save scan results to log file"""
        log_file = "/tmp/urlscan.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(log_file, "a") as f:
            f.write(f"\n[{timestamp}] Scan Results:\n")
            f.write(f"URL: {results['url']}\n")
            f.write(f"Status: {results['status']}\n")
            f.write(f"Score: {results['details'].get('risk_score', 0)}\n")
            f.write(f"Issues: {len(results['issues'])}\n")
            if results['issues']:
                for issue in results['issues']:
                    f.write(f"  - {issue}\n")
            f.write("-"*40 + "\n")
        
        print(f"\n📝 Log saved to: {log_file}")
    
    def batch_scan(self, file_path):
        """Scan multiple URLs from file"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"\n📁 Batch scanning {len(urls)} URLs...")
            
            results = []
            for url in urls:
                result = self.check_url(url)
                results.append(result)
                self.display_results(result)
            
            # Summary
            safe_count = sum(1 for r in results if 'SAFE' in r['status'])
            risky_count = sum(1 for r in results if 'RISK' in r['status'])
            
            print("\n" + "📈 BATCH SUMMARY".center(50, "="))
            print(f"Total URLs: {len(urls)}")
            print(f"Safe: {safe_count}")
            print(f"Risky: {risky_count}")
            print(f"High Risk: {sum(1 for r in results if 'HIGH' in r['status'])}")
            
        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")
        except Exception as e:
            print(f"❌ Error: {str(e)}")

def main():
    scanner = URLScanner()
    scanner.print_banner()
    
    print("Options:")
    print("  1. Scan single URL")
    print("  2. Scan multiple URLs from file")
    print("  3. Check local file (phishing detection)")
    print("  4. Exit")
    
    try:
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            url = input("Enter URL to scan: ").strip()
            if url:
                results = scanner.check_url(url)
                scanner.display_results(results)
            else:
                print("❌ Please enter a URL")
        
        elif choice == '2':
            file_path = input("Enter file path with URLs (one per line): ").strip()
            if file_path and os.path.exists(file_path):
                scanner.batch_scan(file_path)
            else:
                print("❌ File not found")
        
        elif choice == '3':
            file_path = input("Enter local HTML file path: ").strip()
            if file_path and os.path.exists(file_path):
                # Simple phishing page detection
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                
                phishing_indicators = ['password', 'login', 'username', 'bank', 'verify']
                found = [ind for ind in phishing_indicators if ind in content]
                
                print(f"\nPhishing indicators found: {len(found)}")
                if found:
                    print("Indicators:", ', '.join(found[:5]))
                
                if len(found) > 3:
                    print("🚨 WARNING: This looks like a phishing page!")
                else:
                    print("✅ No strong phishing indicators found")
        
        elif choice == '4':
            print("👋 Goodbye!")
            sys.exit(0)
        
        else:
            print("❌ Invalid choice")
    
    except KeyboardInterrupt:
        print("\n\n👋 Scan cancelled!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    # Check for required packages
    try:
        import requests
    except ImportError:
        print("Installing required packages...")
        os.system("pip3 install requests 2>/dev/null || pip install requests")
        import requests
    
    main()
