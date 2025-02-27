import jwt
import datetime
import secrets

class TokenGenerator:
    """
    Generates session tokens with various security properties for testing purposes.
    """
    
    def __init__(self, secret_key=None):
        """
        Initialize the token generator with an optional secret key.
        If not provided, a random key will be generated.
        """
        self.secret_key = secret_key or secrets.token_hex(16)
        
        # Define security levels with specific properties
        self.security_levels = {
            'high': {
                'algorithm': 'HS256',
                'expiration': 3600,  # 1 hour
                'http_only': True,
                'secure': True,
                'same_site': 'Strict'
            },
            'medium': {
                'algorithm': 'HS256',
                'expiration': 86400,  # 24 hours
                'http_only': True,
                'secure': False,
                'same_site': 'Lax'
            },
            'low': {
                'algorithm': 'none',  # Insecure algorithm
                'expiration': 604800,  # 7 days
                'http_only': False,
                'secure': False,
                'same_site': None
            }
        }
    
    def create_token(self, user_id, security_level='high', additional_data=None):
        """
        Create a JWT token with the specified security level.
        
        Args:
            user_id (str): The user identifier to include in the token
            security_level (str): The security level to use ('high', 'medium', 'low')
            additional_data (dict): Additional data to include in the token
            
        Returns:
            str: The generated token
            dict: The token settings used
        """
        if security_level not in self.security_levels:
            raise ValueError(f"Unknown security level: {security_level}")
            
        settings = self.security_levels[security_level]
        
        # Create the base payload
        payload = {
            'sub': user_id,
            'iat': datetime.datetime.utcnow(),
            'security_level': security_level
        }
        
        # Add expiration if specified
        if settings['expiration']:
            payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=settings['expiration'])
        
        # Add any additional data
        if additional_data:
            payload.update(additional_data)
        
        # Handle the 'none' algorithm case specially
        if settings['algorithm'] == 'none':
            token = jwt.encode(payload, '', algorithm='none')
        else:
            token = jwt.encode(payload, self.secret_key, algorithm=settings['algorithm'])
        
        return token, settings
    
    def create_vulnerable_token(self, user_id, vulnerability_type, additional_data=None):
        """
        Create a token with a specific vulnerability for testing.
        
        Args:
            user_id (str): The user identifier
            vulnerability_type (str): The type of vulnerability to create
            additional_data (dict): Additional data to include
            
        Returns:
            str: The vulnerable token
            str: Description of the vulnerability
        """
        additional_data = additional_data or {}
        
        if vulnerability_type == 'expired':
            # Create an expired token
            payload = {
                'sub': user_id,
                'iat': datetime.datetime.utcnow() - datetime.timedelta(days=2),
                'exp': datetime.datetime.utcnow() - datetime.timedelta(days=1),
                'security_level': 'high',
                **additional_data
            }
            token = jwt.encode(payload, self.secret_key, algorithm='HS256')
            description = "Expired token (expiration date in the past)"
            
        elif vulnerability_type == 'no_signature':
            # Create a token with 'none' algorithm (no signature)
            payload = {
                'sub': user_id,
                'iat': datetime.datetime.utcnow(),
                'security_level': 'low',
                **additional_data
            }
            token = jwt.encode(payload, '', algorithm='none')
            description = "Token with 'none' algorithm (no signature verification)"
            
        elif vulnerability_type == 'weak_secret':
            # Create a token with a weak secret
            payload = {
                'sub': user_id,
                'iat': datetime.datetime.utcnow(),
                'security_level': 'medium',
                **additional_data
            }
            token = jwt.encode(payload, "weak", algorithm='HS256')
            description = "Token with weak secret key (vulnerable to brute force)"
            
        elif vulnerability_type == 'missing_expiration':
            # Create a token without expiration
            payload = {
                'sub': user_id,
                'iat': datetime.datetime.utcnow(),
                'security_level': 'low',
                **additional_data
            }
            token = jwt.encode(payload, self.secret_key, algorithm='HS256')
            description = "Token without expiration date (never expires)"
            
        elif vulnerability_type == 'tampered':
            # Create a valid token, then modify a claim without updating signature
            payload = {
                'sub': user_id,
                'iat': datetime.datetime.utcnow(),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                'security_level': 'high',
                **additional_data
            }
            valid_token = jwt.encode(payload, self.secret_key, algorithm='HS256')
            
            # Decode without verification to modify
            parts = valid_token.split('.')
            header_b64 = parts[0]
            
            # Modify the payload to escalate privileges
            decoded_payload = jwt.decode(valid_token, options={"verify_signature": False})
            decoded_payload['role'] = 'admin'  # Add admin role
            
            # Re-encode payload only
            modified_payload_b64 = jwt.utils.base64url_encode(
                jwt.utils.json.dumps(decoded_payload).encode()
            ).decode()
            
            # Keep the original signature
            signature = parts[2]
            
            # Reconstruct the tampered token
            token = f"{header_b64}.{modified_payload_b64}.{signature}"
            description = "Tampered token (modified payload with original signature)"
            
        else:
            raise ValueError(f"Unknown vulnerability type: {vulnerability_type}")
            
        return token, description
    
    def decode_token(self, token, verify=True):
        """
        Decode a token and return its contents.
        
        Args:
            token (str): The token to decode
            verify (bool): Whether to verify the signature
            
        Returns:
            dict: The decoded token payload
        """
        try:
            if verify:
                return jwt.decode(token, self.secret_key, algorithms=['HS256'])
            else:
                return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return {"error": str(e)}