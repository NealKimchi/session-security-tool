import datetime
from typing import Dict, Any, Tuple, Optional

class ExpirationChecker:
    """
    Specialized component for checking JWT token expiration and lifetime.
    """
    
    def __init__(self):
        self.expiration_issues = []
    
    def check(self, token_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform detailed expiration analysis on the JWT token.
        
        Args:
            token_data: Parsed token data from TokenParser
            
        Returns:
            Dictionary with expiration analysis results
        """
        self.expiration_issues = []
        payload = token_data.get("payload", {})
        
        expiry_time = token_data.get("expiry_time")
        issue_time = token_data.get("issue_time")
        now = datetime.datetime.now(datetime.timezone.utc)
        
        result = {
            "has_expiration": "exp" in payload,
            "is_expired": token_data.get("is_expired", False),
            "time_until_expiry": None,
            "total_lifetime": None,
            "time_since_issue": None,
            "percentage_lifetime_remaining": None,
            "issues": []
        }
        
        # Calculate time until expiry if not yet expired
        if expiry_time and not result["is_expired"]:
            time_until_expiry = expiry_time - now
            result["time_until_expiry"] = {
                "days": time_until_expiry.days,
                "hours": time_until_expiry.seconds // 3600,
                "minutes": (time_until_expiry.seconds % 3600) // 60,
                "seconds": time_until_expiry.seconds % 60
            }
            
            # Check if token is about to expire
            if time_until_expiry.total_seconds() < 3600:  # Less than 1 hour
                self._add_issue(
                    "token_expiring_soon",
                    f"Token will expire in less than 1 hour",
                    "Medium"
                )
        
        # Calculate total lifetime if both issue and expiry times are available
        if expiry_time and issue_time:
            total_lifetime = expiry_time - issue_time
            result["total_lifetime"] = {
                "days": total_lifetime.days,
                "hours": total_lifetime.seconds // 3600,
                "minutes": (total_lifetime.seconds % 3600) // 60,
                "seconds": total_lifetime.seconds % 60,
                "total_seconds": total_lifetime.total_seconds()
            }
            
            # Calculate lifetime-related metrics
            if not result["is_expired"]:
                time_since_issue = now - issue_time
                result["time_since_issue"] = {
                    "days": time_since_issue.days,
                    "hours": time_since_issue.seconds // 3600,
                    "minutes": (time_since_issue.seconds % 3600) // 60,
                    "seconds": time_since_issue.seconds % 60
                }
                
                # Calculate percentage of lifetime remaining
                elapsed_seconds = time_since_issue.total_seconds()
                total_seconds = total_lifetime.total_seconds()
                
                if total_seconds > 0:
                    percentage_elapsed = (elapsed_seconds / total_seconds) * 100
                    result["percentage_lifetime_remaining"] = max(0, 100 - percentage_elapsed)
                    
                    # Check if token has consumed most of its lifetime
                    if percentage_elapsed > 80 and not result["is_expired"]:
                        self._add_issue(
                            "token_mostly_consumed",
                            f"Token has consumed more than 80% of its lifetime",
                            "Low"
                        )
            
            # Assess token lifetime security
            if total_lifetime.total_seconds() > 604800:  # 7 days
                self._add_issue(
                    "excessive_lifetime",
                    f"Token lifetime exceeds 7 days ({total_lifetime.days} days)",
                    "High"
                )
            elif total_lifetime.total_seconds() > 86400:  # 1 day
                self._add_issue(
                    "extended_lifetime",
                    f"Token lifetime exceeds 24 hours ({total_lifetime.days} days, {total_lifetime.seconds // 3600} hours)",
                    "Medium"
                )
        
        # Check if no expiration time is set
        if not result["has_expiration"]:
            self._add_issue(
                "no_expiration",
                "Token does not have an expiration time",
                "Critical"
            )
        
        # Check for 'not before' claim
        if "nbf" not in payload:
            self._add_issue(
                "missing_nbf",
                "Token is missing the 'nbf' (not before) claim",
                "Low"
            )
        else:
            nbf_time = datetime.datetime.fromtimestamp(
                payload["nbf"], 
                tz=datetime.timezone.utc
            )
            
            # Check if nbf is in the future
            if nbf_time > now:
                time_until_valid = nbf_time - now
                self._add_issue(
                    "future_nbf",
                    f"Token is not yet valid, will become valid in {time_until_valid.days} days, "
                    f"{time_until_valid.seconds // 3600} hours",
                    "Medium"
                )
        
        result["issues"] = self.expiration_issues
        return result
    
    def _add_issue(self, id: str, description: str, severity: str):
        """Add an expiration-related issue to the list."""
        self.expiration_issues.append({
            "id": id,
            "description": description,
            "severity": severity
        })