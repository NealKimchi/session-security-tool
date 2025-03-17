#!/usr/bin/env python
"""
Test script for session management analysis tool.
This generates sample tokens with various security levels and analyzes them.
"""

import sys
import os
import jwt 
import datetime
import json
from typing import Dict, Any

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import analyzer
from src.analyzer.session_analyzer import SessionAnalyzer

def generate_sample_tokens() -> Dict[str, Any]:
    """Generate sample JWTs with various security levels for testing."""
    # Current time
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Create tokens with different security levels
    tokens = {
        "high_security": jwt.encode(
            {
                "sub": "user123",
                "name": "John Doe",
                "role": "user",
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
                "nbf": int(now.timestamp()),
                "iss": "secure-app",
                "aud": "api",
                "jti": "random-uuid-123"
            },
            "strong_secret_key_1234567890",
            algorithm="HS256"
        ),
        "medium_security": jwt.encode(
            {
                "sub": "user456",
                "name": "Jane Smith",
                "role": "user",
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(days=1)).timestamp())
            },
            "medium_key",
            algorithm="HS256"
        ),
        "low_security": jwt.encode(
            {
                "sub": "user789",
                "name": "Bob Brown",
                "role": "user",
                "exp": int((now + datetime.timedelta(days=7)).timestamp())
            },
            "weak_secret",
            algorithm="HS256"
        ),
        "vulnerable_none_alg": jwt.encode(
            {
                "sub": "admin",
                "name": "Administrator",
                "role": "admin"
            },
            None,  # Changed from "any_key" to None
            algorithm="none
        ),
        "expired_token": jwt.encode(
            {
                "sub": "user101",
                "name": "Expired User",
                "role": "user",
                "iat": int((now - datetime.timedelta(days=2)).timestamp()),
                "exp": int((now - datetime.timedelta(days=1)).timestamp())
            },
            "expired_key",
            algorithm="HS256"
        ),
        "excessive_privileges": jwt.encode(
            {
                "sub": "admin",
                "name": "Super Admin",
                "role": "admin",
                "permissions": ["*", "admin", "read", "write", "delete"],
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(days=30)).timestamp())
            },
            "admin_key",
            algorithm="HS256"
        ),
        "sensitive_data": jwt.encode(
            {
                "sub": "user202",
                "name": "Sensitive Data User",
                "email": "user@example.com",
                "credit_card": "4111-1111-1111-1111",
                "password": "hashed_password_here",
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(days=1)).timestamp())
            },
            "data_key",
            algorithm="HS256"
        )
    }
    
    return tokens

def run_tests():
    """Run analysis on sample tokens."""
    # Generate sample tokens
    sample_tokens = generate_sample_tokens()
    
    # Initialize analyzer
    analyzer = SessionAnalyzer()
    
    # Create results directory if it doesn't exist
    os.makedirs("test_results", exist_ok=True)
    
    # Analyze each token
    for token_name, token in sample_tokens.items():
        print(f"Analyzing {token_name}...")
        
        # Perform analysis
        result = analyzer.analyze_token(token)
        
        # Try to exploit vulnerabilities
        exploits = analyzer.attempt_exploits(token)
        result["exploits"] = exploits
        
        # Save results to file
        with open(f"test_results/{token_name}_analysis.json", 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        print(f"  - Risk Level: {result['risk_assessment']['risk_level']}")
        print(f"  - Vulnerabilities: {len(result['vulnerabilities'])}")
        print(f"  - Threats: {len(result['threats'])}")
        
        # Print exploitability
        exploit_success = False
        for exploit_name, exploit_data in exploits.items():
            if exploit_data.get("success"):
                exploit_success = True
                print(f"  - Vulnerable to {exploit_name}")
        
        if not exploit_success:
            print("  - Not exploitable with tested methods")
        
        print()
    
    print("Testing complete. Results saved to test_results/ directory.")

if __name__ == "__main__":
    run_tests()