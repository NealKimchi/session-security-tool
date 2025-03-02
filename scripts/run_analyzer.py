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

# Dictionary of detailed explanations for vulnerabilities
VULNERABILITY_DETAILS = {
    # Algorithm vulnerabilities
    "missing_algorithm": {
        "reason": "Without a specified algorithm, the server might default to an insecure verification method.",
        "technical_details": "The JWT standard requires the 'alg' field in the header to indicate how the token should be verified.",
        "attack_vector": "An attacker could modify the token and bypass signature verification if the server doesn't properly validate the algorithm.",
        "impact": "Authentication bypass and potential account takeover.",
        "remediation": "Always specify a secure algorithm in JWT headers and validate it on the server side."
    },
    "none_algorithm": {
        "reason": "The 'none' algorithm tells servers to skip signature verification entirely.",
        "technical_details": "When a token uses the 'none' algorithm, servers should reject it. However, some implementations incorrectly accept such tokens as valid.",
        "affected_code": "if (algorithm.toLowerCase() === 'none') {\n  // Vulnerable: skipping signature verification\n  return true;\n}",
        "attack_vector": "An attacker can modify the token payload and set the algorithm to 'none', potentially bypassing authentication.",
        "impact": "Complete authentication bypass, allowing attackers to impersonate any user or gain unauthorized privileges.",
        "remediation": "Always validate the algorithm and reject tokens using the 'none' algorithm. Whitelist allowed algorithms instead of blacklisting."
    },
    "weak_algorithm": {
        "reason": "This algorithm is known to have security weaknesses that can be exploited by attackers.",
        "technical_details": "Weak algorithms like HS1, RS1, or ES1 use insufficient cryptographic strength and can be vulnerable to various cryptographic attacks.",
        "attack_vector": "Depending on the algorithm, attacks might include collision attacks, brute forcing, or other cryptographic weaknesses.",
        "impact": "Token forgery, allowing attackers to create valid tokens with arbitrary claims.",
        "remediation": "Use strong, industry-standard algorithms such as HS256, RS256, or ES256."
    },
    "uncommon_algorithm": {
        "reason": "Non-standard algorithms may not be thoroughly tested or could have unknown vulnerabilities.",
        "technical_details": "Using uncommon algorithms increases the risk of implementation errors or undiscovered vulnerabilities.",
        "impact": "Potential security issues if the algorithm has undiscovered weaknesses or implementation flaws.",
        "remediation": "Stick to well-established algorithms like HS256, RS256, or ES256 that have undergone extensive security review."
    },
    
    # Expiration vulnerabilities
    "no_expiration": {
        "reason": "Tokens without expiration never become invalid, extending the attack window indefinitely if compromised.",
        "technical_details": "The token is missing the 'exp' claim which defines when a token should no longer be accepted.",
        "attack_vector": "If a token is stolen or leaked, an attacker can use it indefinitely.",
        "impact": "Permanent account compromise if a token is leaked or stolen.",
        "remediation": "Always include an 'exp' claim in your tokens and set reasonable lifetimes based on the security requirements."
    },
    "expired_token": {
        "reason": "Using expired tokens indicates a failure in token validation or an attempt to use old credentials.",
        "technical_details": "The token's 'exp' claim indicates it has expired and should no longer be accepted.",
        "impact": "Potential replay attacks or unauthorized access if expired tokens are still accepted.",
        "remediation": "Always verify token expiration on the server and immediately reject expired tokens."
    },
    "long_expiration": {
        "reason": "Long-lived tokens remain valid for extended periods, increasing the risk if they're compromised.",
        "technical_details": "This token has a lifetime exceeding 7 days, which is considered excessive for most applications.",
        "impact": "Extended window of opportunity for attackers if the token is compromised.",
        "remediation": "Reduce token lifetime to match security requirements. For sensitive operations, use short-lived tokens (minutes to hours)."
    },
    
    # Missing claims
    "missing_claims": {
        "reason": "Standard claims enhance security by allowing more precise validation of the token's intended use.",
        "technical_details": "Important JWT claims like issuer (iss), audience (aud), or issued-at (iat) are missing, limiting validation options.",
        "impact": "Reduced ability to enforce proper token usage and validation checks.",
        "remediation": "Include standard claims like 'iss', 'aud', 'iat', 'nbf', and 'jti' in your tokens to enable proper validation."
    },
    
    # Key-related vulnerabilities
    "short_signature": {
        "reason": "Short signatures may indicate weak cryptographic security that can be brute-forced.",
        "technical_details": "The signature length suggests inadequate cryptographic strength, potentially allowing attackers to forge valid signatures.",
        "impact": "Potential token forgery if the signature can be brute-forced or predicted.",
        "remediation": "Use strong keys with appropriate length (at least 256 bits for symmetric algorithms)."
    },
    "potential_weak_key": {
        "reason": "The token appears to be signed with a predictable or commonly used secret key.",
        "technical_details": "The signature indicates the use of a weak secret key that might be guessable or commonly used in examples.",
        "attack_vector": "Attackers can try common keys to forge valid tokens if they can guess the secret.",
        "impact": "Authentication bypass and privilege escalation if the key is compromised.",
        "remediation": "Use a strong, randomly generated secret key for signing tokens. The key should be at least 256 bits (32 bytes) of entropy."
    },
    
    # Privilege-related vulnerabilities
    "admin_privileges": {
        "reason": "Administrative tokens should be short-lived and carefully restricted due to their elevated access.",
        "technical_details": "The token includes administrative privileges that grant extensive access to the system.",
        "impact": "Elevated privileges could lead to significant damage if the token is compromised.",
        "remediation": "Use short-lived admin tokens, implement privilege separation, and follow the principle of least privilege."
    },
    "wildcard_permissions": {
        "reason": "Wildcard permissions grant excessive access, violating the principle of least privilege.",
        "technical_details": "The token contains permission values like '*', 'all', or 'full' that grant broad or unlimited access.",
        "impact": "Excessive privileges could allow an attacker to access unauthorized resources or perform unauthorized actions.",
        "remediation": "Grant only the specific permissions needed for the intended operations. Avoid wildcard permissions."
    },
    
    # Sensitive data
    "sensitive_email": {
        "reason": "JWT tokens are only encoded, not encrypted. Sensitive data can be read by anyone with access to the token.",
        "technical_details": "The token contains an email address, which could be used for phishing or other targeted attacks.",
        "impact": "Privacy breach and potential for targeted attacks.",
        "remediation": "Store only identifiers in the token, not sensitive personal information. Keep sensitive data on the server."
    },
    "sensitive_credit_card": {
        "reason": "Credit card information should never be stored in a JWT as it's visible to anyone who can access the token.",
        "technical_details": "The token contains what appears to be credit card information, which represents a serious security risk.",
        "impact": "Compliance violations (PCI DSS) and financial fraud risk.",
        "remediation": "Never store sensitive financial information in tokens. Store only non-sensitive identifiers."
    }
}

# Dictionary of detailed explanations for threats
THREAT_DETAILS = {
    "malformed_token": {
        "reason": "The token structure has been altered from the standard JWT format, suggesting tampering.",
        "technical_details": "A valid JWT must consist of three parts separated by dots: header.payload.signature. This token doesn't follow that structure."
    },
    "header_mismatch": {
        "reason": "The decoded header doesn't match what was expected, indicating the token has been tampered with.",
        "technical_details": "The header portion of the JWT has been modified after the token was created, which invalidates the signature."
    },
    "none_algorithm_attack": {
        "reason": "This is a deliberate attempt to bypass signature verification by exploiting vulnerable implementations.",
        "technical_details": "Some JWT libraries incorrectly accept tokens with the 'none' algorithm, allowing attackers to modify the payload without invalidating the signature."
    },
    "algorithm_confusion_attack": {
        "reason": "The token contains suspicious 'kid' (key ID) values that may be attempting to exploit directory traversal or injection vulnerabilities.",
        "technical_details": "Attackers can manipulate the 'kid' parameter to trick the server into using a different key or file for verification."
    },
    "blank_password_attack": {
        "reason": "The token appears to be signed with an empty secret, which could bypass security in vulnerable implementations.",
        "technical_details": "Some JWT implementations incorrectly accept tokens signed with an empty string as the secret key."
    },
    "jku_header_attack": {
        "reason": "The 'jku' header can be manipulated to load keys from attacker-controlled locations.",
        "technical_details": "Attackers can set the 'jku' (JWK Set URL) header to point to their own JWK set, potentially tricking the server into using the attacker's keys for verification."
    },
    "role_type_confusion": {
        "reason": "The token contains role information in a format that might confuse type-checking mechanisms.",
        "technical_details": "When role or permission data is stored as a string representation of an array or object, it can potentially bypass type checking in the application."
    },
    "missing_jti": {
        "reason": "Without a unique identifier (jti claim), it's harder to implement token revocation or detect token reuse.",
        "technical_details": "The 'jti' (JWT ID) claim provides a unique identifier for the token, which is essential for maintaining a token blacklist or detecting replay attacks."
    },
    "potential_brute_force": {
        "reason": "The unusually short signature suggests this token may be part of a brute force attempt.",
        "technical_details": "Short signatures can indicate that the token is being used in a brute force attack to discover the secret key."
    },
    "embedded_key": {
        "reason": "The token contains an embedded key in the header, which could be an attempt to control the verification process.",
        "technical_details": "The 'jwk' header parameter contains a JSON Web Key that some implementations might use for verification instead of the server's trusted keys."
    },
    "signature_stripping": {
        "reason": "The token has an empty signature, which may be an attempt to bypass signature verification.",
        "technical_details": "This technique attempts to exploit implementations that don't properly validate the signature component of the token."
    }
}

# Dictionary of detailed explanations for exploits
EXPLOIT_DETAILS = {
    "none_algorithm": {
        "reason": "The server accepted a token with the 'none' algorithm, completely bypassing signature verification.",
        "technical_details": "By changing the algorithm to 'none' and removing the signature, the server incorrectly accepted the token as valid.",
        "proof_of_concept": "Original algorithm: HS256\nModified token with 'none' algorithm: [header].[payload].",
        "impact": "Full authentication bypass, allowing attackers to forge tokens with arbitrary content.",
        "mitigation": "Explicitly check for and reject tokens using the 'none' algorithm. Always verify signatures using the expected algorithm."
    },
    "header_manipulation": {
        "reason": "The server accepted a token with manipulated header parameters that control verification.",
        "technical_details": "By adding a 'jwk' parameter to the header, the server was tricked into using an attacker-supplied key for verification.",
        "proof_of_concept": "Added malicious 'jwk' parameter to the header to control verification.",
        "impact": "Authentication bypass by controlling which key is used for verification.",
        "mitigation": "Ignore untrusted header parameters like 'jwk', 'jku', 'x5u' from tokens, or use a whitelist of allowed header parameters."
    },
    "weak_key": {
        "reason": "The token is signed with a weak, easily guessable secret key.",
        "technical_details": "The signature was verified using a common weak key from a list of known default or example keys.",
        "proof_of_concept": "Successfully verified the token using the key: '{cracked_secret}'",
        "impact": "Anyone can create valid tokens by using the same weak key, leading to full authentication bypass.",
        "mitigation": "Use a strong, randomly generated secret key with at least 32 bytes of entropy, and keep it secure."
    }
}

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
        
        # Enhance vulnerabilities with detailed explanations
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id")
            if vuln_id in VULNERABILITY_DETAILS:
                details = VULNERABILITY_DETAILS[vuln_id]
                for key, value in details.items():
                    vuln[key] = value
                    
            # If the vulnerability is not in our details dictionary, add generic reasons
            else:
                vuln["reason"] = "This vulnerability could expose the application to security risks."
                vuln["impact"] = "Potential security breach depending on the context of the vulnerability."
                vuln["remediation"] = "Review and fix the identified security issue according to best practices."
        
        result["vulnerabilities"] = vulnerabilities
        
        # Detect threats
        threats = threat_detector.detect(token_data, token)
        
        # Enhance threats with detailed explanations
        for threat in threats:
            threat_id = threat.get("id")
            if threat_id in THREAT_DETAILS:
                details = THREAT_DETAILS[threat_id]
                for key, value in details.items():
                    threat[key] = value
            # Add generic reason if not found
            else:
                threat["reason"] = "This represents a potential security threat to your application."
                threat["technical_details"] = "The token contains patterns or characteristics that could be exploited by attackers."
        
        result["threats"] = threats
        
        # Attempt exploits if requested
        if attempt_exploits:
            exploits = threat_detector.attempt_exploit(token)
            
            # Enhance exploits with detailed explanations
            for name, exploit in exploits.items():
                if name in EXPLOIT_DETAILS:
                    details = EXPLOIT_DETAILS[name]
                    for key, value in details.items():
                        # Special case for weak key exploit
                        if key == "proof_of_concept" and name == "weak_key" and exploit.get("success"):
                            exploit[key] = value.replace("{cracked_secret}", str(exploit.get("cracked_secret", "unknown")))
                        else:
                            exploit[key] = value
                
                # Add descriptions for any exploits without details
                if exploit.get("success") and "reason" not in exploit:
                    exploit["reason"] = "This exploit was successful, indicating a vulnerability in the token validation."
                    exploit["impact"] = "Potential security bypass depending on how the token is used."
                    exploit["mitigation"] = "Review and strengthen the token validation mechanisms."
            
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
            print(f"  Description: {vuln.get('description', '')}")
            if "reason" in vuln:
                print(f"  Why vulnerable: {vuln.get('reason', '')}")
            if "remediation" in vuln:
                print(f"  Remediation: {vuln.get('remediation', '')}")
            print("")
    else:
        print("\n--- Vulnerabilities ---")
        print("No vulnerabilities detected.")
    
    # Print threats
    threats = result.get("threats", [])
    if threats:
        print("\n--- Security Threats ---")
        for threat in threats:
            print(f"- {threat.get('title', 'Unknown')} (Severity: {threat.get('severity', 'Unknown')})")
            print(f"  Description: {threat.get('description', '')}")
            if "reason" in threat:
                print(f"  Why this is a threat: {threat.get('reason', '')}")
            print("")
    else:
        print("\n--- Security Threats ---")
        print("No security threats detected.")
    
    # Print exploits if available
    if "exploits" in result:
        print("\n--- Exploit Attempts ---")
        for name, exploit in result["exploits"].items():
            status = "Vulnerable!" if exploit.get("success") else "Not vulnerable"
            print(f"- {name}: {status}")
            if exploit.get("success") and "reason" in exploit:
                print(f"  Why vulnerable: {exploit.get('reason', '')}")
                if "mitigation" in exploit:
                    print(f"  Mitigation: {exploit.get('mitigation', '')}")
            print("")
    
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