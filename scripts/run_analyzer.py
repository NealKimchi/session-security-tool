#!/usr/bin/env python
"""
Simple script to analyze JWT tokens from the command line.
No external JWT libraries are required.

Usage:
  python run_analyzer.py <JWT_TOKEN>
  python run_analyzer.py -f token.txt
"""

import sys
import os
import json
import argparse
from datetime import datetime

current_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(current_dir)
from src.analyzer.token_parser import TokenParser
from src.analyzer.vulnerability_scanner import VulnerabilityScanner
from src.analyzer.expiration_checker import ExpirationChecker
from src.analyzer.threat_detector import ThreatDetector

def analyze_token(token, secret_key=None, attempt_exploits=False):
    """
    Analyze a JWT token without requiring the full SessionAnalyzer class.
    
    This is a simplified version that does the same analysis but with fewer dependencies.
    """
    # Initialize components
    token_parser = TokenParser()
    vulnerability_scanner = VulnerabilityScanner()
    expiration_checker = ExpirationChecker()
    threat_detector = ThreatDetector()
    
    result = {
        "token": token,
        "timestamp": datetime.now().isoformat(),
        "overview": {},
        "token_data": {},
        "vulnerabilities": [],
        "threats": []
    }
    
    try:
        # Parse the token
        token_data = token_parser.parse(token)
        result["token_data"] = token_data
        
        # Basic overview
        header = token_data.get("header", {})
        payload = token_data.get("payload", {})
        
        result["overview"] = {
            "algorithm": header.get("alg", "unknown"),
            "token_type": header.get("typ", "JWT"),
            "is_expired": token_data.get("is_expired", False),
            "issuer": payload.get("iss", "unknown"),
            "subject": payload.get("sub", "unknown"),
        }
        
        # Check expiration
        expiration_result = expiration_checker.check(token_data)
        result["expiration_analysis"] = expiration_result
        
        # Scan for vulnerabilities
        vulnerabilities = vulnerability_scanner.scan(token_data)
        result["vulnerabilities"] = vulnerabilities
        
        # Detect threats
        threats = threat_detector.detect(token_data, token)
        result["threats"] = threats
        
        # Attempt exploits if requested
        if attempt_exploits:
            exploits = threat_detector.attempt_exploit(token)
            result["exploits"] = exploits
        
        return result
    
    except Exception as e:
        return {
            "error": str(e),
            "token": token
        }

def print_simple_report(result):
    """Print a simplified report to the console."""
    print("\n=== JWT Token Analysis ===")
    print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if "error" in result:
        print(f"\nERROR: {result['error']}")
        return
    
    # Print basic info
    print("\n--- Token Overview ---")
    overview = result.get("overview", {})
    for key, value in overview.items():
        print(f"{key}: {value}")
    
    # Print token data
    token_data = result.get("token_data", {})
    print("\n--- Token Header ---")
    print(json.dumps(token_data.get("header", {}), indent=2))
    
    print("\n--- Token Payload ---")
    print(json.dumps(token_data.get("payload", {}), indent=2))
    
    # Print vulnerabilities
    vulnerabilities = result.get("vulnerabilities", [])
    if vulnerabilities:
        print("\n--- Vulnerabilities ---")
        for vuln in vulnerabilities:
            print(f"- {vuln.get('title', 'Unknown')} (Severity: {vuln.get('severity', 'Unknown')})")
    else:
        print("\n--- Vulnerabilities ---")
        print("No vulnerabilities detected.")
    
    # Print threats
    threats = result.get("threats", [])
    if threats:
        print("\n--- Security Threats ---")
        for threat in threats:
            print(f"- {threat.get('title', 'Unknown')} (Severity: {threat.get('severity', 'Unknown')})")
    else:
        print("\n--- Security Threats ---")
        print("No security threats detected.")
    
    # Print exploits if available
    if "exploits" in result:
        print("\n--- Exploit Attempts ---")
        for name, exploit in result["exploits"].items():
            status = "Vulnerable!" if exploit.get("success") else "Not vulnerable"
            print(f"- {name}: {status}")
    
    print("\n=== End of Analysis ===")

def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(description="Simple JWT Token Analyzer")
    
    # Create a mutually exclusive group for token input
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument("token", nargs="?", help="JWT token to analyze")
    token_group.add_argument("-f", "--file", help="File containing JWT token")
    
    # Other options
    parser.add_argument("-s", "--secret", help="Secret key for signature verification")
    parser.add_argument("-e", "--exploits", action="store_true", help="Attempt to exploit vulnerabilities")
    parser.add_argument("-o", "--output", help="Save report to JSON file")
    
    args = parser.parse_args()
    
    # Get the token
    token = None
    if args.token:
        token = args.token
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                token = f.read().strip()
        except Exception as e:
            print(f"Error reading token file: {str(e)}")
            sys.exit(1)
    
    # Analyze the token
    result = analyze_token(token, args.secret, args.exploits)
    
    # Print the report
    print_simple_report(result)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nReport saved to: {args.output}")

if __name__ == "__main__":
    main()