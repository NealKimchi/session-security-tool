import base64
import json
import datetime
import hmac
import hashlib
from typing import Dict, Any, Tuple, Optional

class TokenParser:
    """
    Parses and validates JWT tokens, extracting headers, payload, and signature.
    This implementation doesn't rely on external JWT libraries.
    """
    
    def __init__(self):
        self.raw_token = None
        self.header = None
        self.payload = None
        self.signature = None
        self.is_expired = None
        self.expiry_time = None
        self.issue_time = None
    
    def parse(self, token: str) -> Dict[str, Any]:
        """
        Parse a JWT token and extract its components.
        
        Args:
            token: The JWT token string
            
        Returns:
            Dict containing the parsed token details
        """
        self.raw_token = token
        
        # Split the token into its three parts
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: Token must have three parts separated by dots")
        
        # Decode header and payload
        try:
            self.header = self._decode_base64_part(parts[0])
            self.payload = self._decode_base64_part(parts[1])
            self.signature = parts[2]  # Keep signature in its encoded form
        except Exception as e:
            raise ValueError(f"Failed to decode token parts: {str(e)}")
        
        # Extract and parse timestamp fields
        self._parse_timestamps()
        
        return {
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "is_expired": self.is_expired,
            "expiry_time": self.expiry_time,
            "issue_time": self.issue_time,
            "raw_token": self.raw_token
        }
    
    def validate(self, secret_key: str = None, algorithms: list = None) -> Tuple[bool, Optional[str]]:
        """
        Validate the JWT token signature.
        
        Args:
            secret_key: Secret key used to sign the token
            algorithms: List of allowed algorithms
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if self.raw_token is None:
            return False, "No token has been parsed yet"
        
        if algorithms is None:
            algorithms = [self.header.get("alg", "HS256")]
        
        # If no secret key is provided, we can only check for expiration
        if secret_key is None:
            return not self.is_expired, "Token is expired" if self.is_expired else None
        
        # Check if token is expired
        if self.is_expired:
            return False, "Token has expired"
            
        # Get the algorithm from header
        alg = self.header.get("alg")
        if not alg:
            return False, "No algorithm specified in token header"
            
        # Verify the token's algorithm is in the allowed list
        if alg not in algorithms:
            return False, f"Invalid algorithm. Expected one of: {algorithms}"
        
        # Split the token
        parts = self.raw_token.split('.')
        if len(parts) != 3:
            return False, "Invalid token format"
        
        # For 'none' algorithm, the signature should be empty
        if alg.lower() == 'none':
            return parts[2] == '', "Invalid signature for 'none' algorithm"
        
        # HS256 verification
        if alg == 'HS256':
            try:
                expected_sig = self._calculate_signature(parts[0], parts[1], secret_key, 'HS256')
                actual_sig = self._base64url_decode(parts[2])
                is_valid = hmac.compare_digest(expected_sig, actual_sig)
                return is_valid, None if is_valid else "Invalid signature"
            except Exception as e:
                return False, f"Signature verification failed: {str(e)}"
        
        # Only HS256 and none are supported in this simplified implementation
        return False, f"Algorithm '{alg}' is not supported by this implementation"
    
    def _decode_base64_part(self, encoded_part: str) -> Dict[str, Any]:
        """
        Decode a base64url encoded part of a JWT token.
        
        Args:
            encoded_part: Base64url encoded string
            
        Returns:
            Decoded JSON as a dictionary
        """
        decoded_bytes = self._base64url_decode(encoded_part)
        decoded_json = json.loads(decoded_bytes.decode('utf-8'))
        
        return decoded_json
    
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
    
    def _base64url_encode(self, input: bytes) -> str:
        """Encode bytes to base64url string."""
        # Encode to base64
        encoded = base64.b64encode(input).decode('ascii')
        
        # Make URL safe
        encoded = encoded.replace('+', '-').replace('/', '_').rstrip('=')
        
        return encoded
    
    def _calculate_signature(self, header_b64: str, payload_b64: str, secret: str, alg: str) -> bytes:
        """Calculate the expected signature for a token."""
        if alg == 'HS256':
            msg = f"{header_b64}.{payload_b64}".encode('ascii')
            signature = hmac.new(
                secret.encode('utf-8'), 
                msg=msg, 
                digestmod=hashlib.sha256
            ).digest()
            return signature
        
        # Add other algorithms as needed
        raise ValueError(f"Unsupported algorithm: {alg}")
    
    def _parse_timestamps(self):
        """Parse and validate timestamp fields from the payload."""
        if not self.payload:
            return
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Check expiration time
        if "exp" in self.payload:
            self.expiry_time = datetime.datetime.fromtimestamp(
                self.payload["exp"], 
                tz=datetime.timezone.utc
            )
            self.is_expired = now > self.expiry_time
        else:
            self.is_expired = False
            self.expiry_time = None
        
        # Check issued at time
        if "iat" in self.payload:
            self.issue_time = datetime.datetime.fromtimestamp(
                self.payload["iat"], 
                tz=datetime.timezone.utc
            )
        else:
            self.issue_time = None