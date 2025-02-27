import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

# Import the components
from .token_parser import TokenParser
from .expiration_checker import ExpirationChecker
from .vulnerability_scanner import VulnerabilityScanner
from .threat_detector import ThreatDetector

class SessionAnalyzer:
    """
    Main class that integrates all components for session token analysis.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the session analyzer with optional configuration.
        
        Args:
            config: Configuration dictionary for the analyzer
        """
        self.config = config or {}
        self.token_parser = TokenParser()
        self.expiration_checker = ExpirationChecker()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.threat_detector = ThreatDetector()
        self.logger = logging.getLogger("session_analyzer")
    
    def analyze_token(self, token: str, secret_key: str = None) -> Dict[str, Any]:
        """
        Analyze a JWT token using all available analyzers.
        
        Args:
            token: The JWT token string
            secret_key: Optional secret key for signature verification
            
        Returns:
            Dictionary with comprehensive analysis results
        """
        result = {
            "token": token,
            "timestamp": datetime.now().isoformat(),
            "overview": {},
            "token_data": {},
            "expiration_analysis": {},
            "vulnerabilities": [],
            "threats": [],
            "risk_assessment": {},
            "recommendations": []
        }
        
        try:
            # Parse the token
            self.logger.info("Parsing token...")
            token_data = self.token_parser.parse(token)
            result["token_data"] = token_data
            
            # Generate overview
            result["overview"] = self._generate_overview(token_data)
            
            # Validate signature if secret key is provided
            if secret_key:
                is_valid, error_msg = self.token_parser.validate(secret_key)
                result["overview"]["signature_valid"] = is_valid
                if error_msg:
                    result["overview"]["validation_error"] = error_msg
            
            # Analyze expiration
            self.logger.info("Analyzing expiration...")
            expiration_analysis = self.expiration_checker.check(token_data)
            result["expiration_analysis"] = expiration_analysis
            
            # Scan for vulnerabilities
            self.logger.info("Scanning for vulnerabilities...")
            vulnerabilities = self.vulnerability_scanner.scan(token_data)
            result["vulnerabilities"] = vulnerabilities
            
            # Detect threats
            self.logger.info("Detecting threats...")
            threats = self.threat_detector.detect(token_data, token)
            result["threats"] = threats
            
            # Generate risk assessment
            result["risk_assessment"] = self._assess_risk(token_data, vulnerabilities, threats, expiration_analysis)
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(token_data, vulnerabilities, threats, expiration_analysis)
            
            return result
        
        except Exception as e:
            self.logger.error(f"Error analyzing token: {str(e)}")
            return {
                "error": str(e),
                "token": token,
                "timestamp": datetime.now().isoformat()
            }
    
    def attempt_exploits(self, token: str) -> Dict[str, Any]:
        """
        Attempt to exploit vulnerabilities in the token.
        This is for educational purposes only.
        
        Args:
            token: The JWT token string
            
        Returns:
            Dictionary with exploit results
        """
        return self.threat_detector.attempt_exploit(token)
    
    def _generate_overview(self, token_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an overview of the token."""
        header = token_data.get("header", {})
        payload = token_data.get("payload", {})
        
        overview = {
            "algorithm": header.get("alg", "unknown"),
            "token_type": header.get("typ", "JWT"),
            "is_expired": token_data.get("is_expired", False),
            "issuer": payload.get("iss", "unknown"),
            "subject": payload.get("sub", "unknown"),
            "audience": payload.get("aud", "unknown"),
            "issued_at": token_data.get("issue_time", "unknown"),
            "expires_at": token_data.get("expiry_time", "unknown"),
        }
        
        # Add key usage information if available
        if "kid" in header:
            overview["key_id"] = header["kid"]
        
        return overview
    
    def _assess_risk(self, 
                    token_data: Dict[str, Any], 
                    vulnerabilities: List[Dict[str, Any]], 
                    threats: List[Dict[str, Any]],
                    expiration_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the overall risk level of the token.
        
        Args:
            token_data: Parsed token data
            vulnerabilities: List of identified vulnerabilities
            threats: List of detected threats
            expiration_analysis: Expiration analysis results
            
        Returns:
            Dictionary with risk assessment details
        """
        # Count vulnerabilities by severity
        vuln_count = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            vuln_count[severity] = vuln_count.get(severity, 0) + 1
            
        for threat in threats:
            severity = threat.get("severity", "Low")
            vuln_count[severity] = vuln_count.get(severity, 0) + 1
            
        # Calculate overall risk score (0-100)
        risk_score = min(100, (
            vuln_count["Critical"] * 25 + 
            vuln_count["High"] * 10 + 
            vuln_count["Medium"] * 5 + 
            vuln_count["Low"] * 1
        ))
        
        # Determine risk level
        risk_level = "Low"
        if risk_score >= 75:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
            
        # Identify the most severe issues
        all_issues = vulnerabilities + threats
        severe_issues = [issue for issue in all_issues if issue.get("severity") in ["Critical", "High"]]
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "vulnerability_count": vuln_count,
            "total_issues": len(vulnerabilities) + len(threats),
            "severe_issues": severe_issues[:5],  # Top 5 most severe issues
            "expiration_risk": "High" if token_data.get("is_expired", False) else (
                "Medium" if any(issue["id"] in ["no_expiration", "long_expiration"] 
                               for issue in expiration_analysis.get("issues", [])) 
                else "Low"
            )
        }
    
    def _generate_recommendations(self, 
                                token_data: Dict[str, Any], 
                                vulnerabilities: List[Dict[str, Any]], 
                                threats: List[Dict[str, Any]],
                                expiration_analysis: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on the analysis results.
        
        Args:
            token_data: Parsed token data
            vulnerabilities: List of identified vulnerabilities
            threats: List of detected threats
            expiration_analysis: Expiration analysis results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Algorithm recommendations
        header = token_data.get("header", {})
        alg = header.get("alg", "")
        if alg not in ["HS256", "RS256", "ES256"]:
            recommendations.append(
                "Use a strong, industry-standard algorithm such as HS256, RS256, or ES256 for token signatures."
            )
        
        # Expiration recommendations
        if "exp" not in token_data.get("payload", {}):
            recommendations.append(
                "Always include an expiration time (exp) claim in your tokens."
            )
        
        # Check for long-lived tokens
        exp_issues = expiration_analysis.get("issues", [])
        if any(issue["id"] in ["excessive_lifetime", "extended_lifetime"] for issue in exp_issues):
            recommendations.append(
                "Reduce token lifetime to minimize the window of opportunity for attackers. "
                "For sensitive operations, consider using short-lived tokens (minutes to hours)."
            )
        
        # Check for missing claims
        if any(vuln["id"] == "missing_claims" for vuln in vulnerabilities):
            recommendations.append(
                "Include recommended JWT claims such as 'iat' (issued at), 'nbf' (not before), "
                "'jti' (JWT ID), 'iss' (issuer), and 'aud' (audience) to enhance security."
            )
        
        # Cookie security recommendations
        recommendations.append(
            "Set secure cookie attributes: HttpOnly (prevents JavaScript access), "
            "Secure (requires HTTPS), and SameSite=Strict (prevents CSRF attacks)."
        )
        
        # Check for sensitive data in payload
        if any(vuln["id"].startswith("sensitive_") for vuln in vulnerabilities):
            recommendations.append(
                "Avoid storing sensitive data in JWT tokens as they are only Base64 encoded, not encrypted. "
                "Store sensitive data in your backend systems instead."
            )
        
        # Secret key recommendations
        if any(vuln["id"] == "potential_weak_key" for vuln in vulnerabilities):
            recommendations.append(
                "Use a strong, randomly generated secret key for signing tokens. "
                "The key should be at least 256 bits (32 bytes) of entropy."
            )
        
        # Privilege recommendations
        if any(vuln["id"] in ["admin_privileges", "wildcard_permissions"] for vuln in vulnerabilities):
            recommendations.append(
                "Follow the principle of least privilege. Only include the permissions "
                "that are strictly necessary for the token's purpose."
            )
        
        # Add a general security practice recommendation
        recommendations.append(
            "Implement token validation on all protected routes, checking for valid signatures, "
            "expiration times, and appropriate scopes/permissions."
        )
        
        # Add key rotation recommendation
        recommendations.append(
            "Rotate signing keys periodically. Implement a key rotation strategy that "
            "allows for seamless transition between old and new keys."
        )
        
        return recommendations

    def get_token_from_cookie(self, cookie_string: str, cookie_name: str = "session") -> Optional[str]:
        """
        Extract JWT token from a cookie string.
        
        Args:
            cookie_string: The HTTP cookie header string
            cookie_name: The name of the cookie containing the token
            
        Returns:
            The token string if found, None otherwise
        """
        cookies = {}
        for item in cookie_string.split(';'):
            if '=' in item:
                name, value = item.strip().split('=', 1)
                cookies[name] = value
        
        return cookies.get(cookie_name)
    
    def get_token_from_header(self, auth_header: str) -> Optional[str]:
        """
        Extract JWT token from an Authorization header.
        
        Args:
            auth_header: The Authorization header value
            
        Returns:
            The token string if found, None otherwise
        """
        if auth_header.startswith('Bearer '):
            return auth_header[7:].strip()
        return None