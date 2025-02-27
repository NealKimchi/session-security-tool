#!/usr/bin/env python
import argparse
import json
import sys
import os
import logging
from datetime import datetime

# Fix import path issues
# Add the project root directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))  # Navigate up two levels
sys.path.insert(0, project_root)
from src.analyzer.session_analyzer import SessionAnalyzer

# Try to import colorama for colored output, but make it optional
try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
    HAS_COLORS = True
except ImportError:
    # Create dummy color constants if colorama is not available
    HAS_COLORS = False
    class DummyColors:
        def __getattr__(self, name):
            return ""
    Fore = DummyColors()
    Style = DummyColors()

def setup_logging(verbose):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )

def print_header(text):
    """Print a formatted header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print("=" * 80)

def print_section(text):
    """Print a formatted section header."""
    print(f"\n{Fore.BLUE}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print("-" * 80)

def format_severity(severity):
    """Format severity with appropriate color."""
    if not HAS_COLORS:
        return f"{severity}"
        
    if severity == "Critical":
        return f"{Fore.RED}{Style.BRIGHT}{severity}{Style.RESET_ALL}"
    elif severity == "High":
        return f"{Fore.RED}{severity}{Style.RESET_ALL}"
    elif severity == "Medium":
        return f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
    elif severity == "Low":
        return f"{Fore.GREEN}{severity}{Style.RESET_ALL}"
    return severity

def print_issue(issue):
    """Print a formatted issue."""
    severity = issue.get("severity", "Unknown")
    title = issue.get("title", "Unknown issue")
    description = issue.get("description", "No description provided")
    
    print(f"  {Fore.WHITE}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(f"  Severity: {format_severity(severity)}")
    print(f"  Description: {description}")
    print()

def print_pretty_json(data):
    """Print pretty-formatted JSON."""
    print(json.dumps(data, indent=2, default=str))

def print_token_data(token_data):
    """Print token data in a readable format."""
    print_section("Token Header")
    print_pretty_json(token_data.get("header", {}))
    
    print_section("Token Payload")
    print_pretty_json(token_data.get("payload", {}))
    
    if token_data.get("is_expired"):
        print(f"{Fore.RED}Token is expired!{Style.RESET_ALL}")
    
    print_section("Timestamps")
    if token_data.get("issue_time"):
        print(f"Issued at: {token_data.get('issue_time')}")
    if token_data.get("expiry_time"):
        print(f"Expires at: {token_data.get('expiry_time')}")

def print_risk_assessment(risk_assessment):
    """Print the risk assessment details."""
    risk_level = risk_assessment.get("risk_level", "Unknown")
    risk_score = risk_assessment.get("risk_score", 0)
    
    # Determine risk color
    if risk_level == "Critical":
        color = Fore.RED + Style.BRIGHT
    elif risk_level == "High":
        color = Fore.RED
    elif risk_level == "Medium":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN
    
    print(f"Risk Level: {color}{risk_level}{Style.RESET_ALL}")
    print(f"Risk Score: {color}{risk_score}/100{Style.RESET_ALL}")
    print()
    
    print("Vulnerability Count:")
    vuln_count = risk_assessment.get("vulnerability_count", {})
    print(f"  Critical: {format_severity('Critical')} - {vuln_count.get('Critical', 0)}")
    print(f"  High: {format_severity('High')} - {vuln_count.get('High', 0)}")
    print(f"  Medium: {format_severity('Medium')} - {vuln_count.get('Medium', 0)}")
    print(f"  Low: {format_severity('Low')} - {vuln_count.get('Low', 0)}")
    
    severe_issues = risk_assessment.get("severe_issues", [])
    if severe_issues:
        print()
        print("Top Severe Issues:")
        for issue in severe_issues:
            print(f"  - {issue.get('title', 'Unknown')}")

def print_recommendations(recommendations):
    """Print recommendations with formatting."""
    print_section("Security Recommendations")
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")

def print_exploits(exploits):
    """Print exploit attempts with formatting."""
    print_section("Exploit Attempts")
    for exploit_name, exploit_data in exploits.items():
        success = exploit_data.get("success", False)
        description = exploit_data.get("description", "No description")
        
        if success:
            status = f"{Fore.RED}{Style.BRIGHT}Vulnerable!{Style.RESET_ALL}"
        else:
            status = f"{Fore.GREEN}Not vulnerable{Style.RESET_ALL}"
        
        print(f"  {Fore.WHITE}{Style.BRIGHT}{exploit_name}{Style.RESET_ALL}")
        print(f"  Status: {status}")
        print(f"  Description: {description}")
        
        if success and exploit_data.get("modified_token"):
            print(f"  Modified Token: {exploit_data.get('modified_token')}")
        elif success and exploit_data.get("cracked_secret"):
            print(f"  Cracked Secret: {exploit_data.get('cracked_secret')}")
        
        print()

def save_report(result, output_file):
    """Save the analysis result to a file."""
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nReport saved to: {output_file}")

def main():
    """Main function that runs the CLI interface."""
    parser = argparse.ArgumentParser(description="JWT Session Security Analyzer")
    
    # Main arguments
    parser.add_argument("--token", "-t", help="JWT token to analyze")
    parser.add_argument("--file", "-f", help="File containing JWT token")
    parser.add_argument("--cookie", "-c", help="Extract token from cookie string")
    parser.add_argument("--cookie-name", default="session", help="Name of the cookie containing the token")
    parser.add_argument("--auth-header", "-a", help="Extract token from Authorization header")
    
    # Analysis options
    parser.add_argument("--secret", "-s", help="Secret key for signature verification")
    parser.add_argument("--exploits", "-e", action="store_true", help="Attempt to exploit known vulnerabilities")
    
    # Output options
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--json", "-j", action="store_true", help="Output raw JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    
    # Initialize the analyzer
    analyzer = SessionAnalyzer()
    
    # Get the token from the provided source
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
    elif args.cookie:
        token = analyzer.get_token_from_cookie(args.cookie, args.cookie_name)
        if not token:
            print(f"Could not extract token from cookie '{args.cookie_name}'")
            sys.exit(1)
    elif args.auth_header:
        token = analyzer.get_token_from_header(args.auth_header)
        if not token:
            print(f"Could not extract token from Authorization header")
            sys.exit(1)
    else:
        print(f"No token provided. Use --token, --file, --cookie, or --auth-header.")
        parser.print_help()
        sys.exit(1)
    
    # Analyze the token
    result = analyzer.analyze_token(token, args.secret)
    
    # Check for analysis errors
    if "error" in result:
        print(f"Error analyzing token: {result['error']}")
        sys.exit(1)
    
    # Try to exploit vulnerabilities if requested
    if args.exploits:
        exploit_results = analyzer.attempt_exploits(token)
        result["exploits"] = exploit_results
    
    # Output as raw JSON if requested
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        if args.output:
            save_report(result, args.output)
        sys.exit(0)
    
    # Print formatted report
    print_header("JWT Session Security Analysis")
    print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Token: {token[:25]}...")
    
    # Print token data
    print_token_data(result["token_data"])
    
    # Print vulnerabilities
    if result["vulnerabilities"]:
        print_section("Vulnerabilities")
        for vuln in result["vulnerabilities"]:
            print_issue(vuln)
    else:
        print_section("Vulnerabilities")
        print(f"{Fore.GREEN}No vulnerabilities detected.{Style.RESET_ALL}")
    
    # Print threats
    if result["threats"]:
        print_section("Security Threats")
        for threat in result["threats"]:
            print_issue(threat)
    else:
        print_section("Security Threats")
        print(f"{Fore.GREEN}No security threats detected.{Style.RESET_ALL}")
    
    # Print exploit results if available
    if "exploits" in result:
        print_exploits(result["exploits"])
    
    # Print risk assessment
    print_section("Risk Assessment")
    print_risk_assessment(result["risk_assessment"])
    
    # Print recommendations
    print_recommendations(result["recommendations"])
    
    # Save report if requested
    if args.output:
        save_report(result, args.output)

if __name__ == "__main__":
    main()