# swiggy_auth.py - Hardcoded IPs, No Proxy, No DNS
import requests
import json
import time
import secrets
import hashlib
import base64
import os
import logging

logger = logging.getLogger(__name__)

class SwiggyAuth:
    """Swiggy OAuth - Hardcoded IPs bypass DNS"""
    
    # Hardcoded Swiggy auth server IPs (from AWS)
    AUTH_IPS = [
        "52.66.52.145",
        "13.127.120.95", 
        "15.207.107.142",
        "3.7.151.166"
    ]
    
    AUTH_HOST = "account.swiggy.com"
    
    def __init__(self, state_dir="/tmp/swiggy"):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Swiggy/4.12.0 (Android; 13)',
            'Accept': 'application/json',
            'Connection': 'keep-alive'
        })
        self.working_ip = None
        
    def _get_endpoint(self, ip):
        """Build endpoint with IP instead of domain"""
        return f"https://{ip}"
    
    def init_session(self, mobile):
        """Initialize auth - tries each IP until one works"""
        for ip in self.AUTH_IPS:
            try:
                logger.info(f"Trying IP: {ip}")
                
                # Use IP directly, but set Host header
                endpoint = self._get_endpoint(ip)
                
                # Init session
                init_resp = self.session.get(
                    f"{endpoint}/api/v1/auth/init",
                    params={"mobile": mobile},
                    headers={"Host": self.AUTH_HOST},
                    timeout=10,
                    verify=False  # Bypass SSL verification for IP
                )
                
                if init_resp.status_code != 200:
                    logger.warning(f"IP {ip} returned {init_resp.status_code}")
                    continue
                
                # Extract CSRF token
                csrf_token = self.session.cookies.get('csrf_token')
                if not csrf_token:
                    csrf_token = init_resp.json().get('csrf_token')
                
                if not csrf_token:
                    logger.warning(f"No CSRF token from IP {ip}")
                    continue
                
                # Generate PKCE
                verifier = secrets.token_urlsafe(64)
                challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(verifier.encode()).digest()
                ).decode().rstrip('=')
                
                # Request OTP
                otp_resp = self.session.post(
                    f"{endpoint}/api/v1/auth/otp",
                    json={
                        "mobile": mobile,
                        "csrf_token": csrf_token,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256"
                    },
                    headers={"Host": self.AUTH_HOST},
                    timeout=10,
                    verify=False
                )
                
                if otp_resp.status_code == 200:
                    self.working_ip = ip
                    logger.info(f"✅ Auth working via IP: {ip}")
                    return {
                        "csrf_token": csrf_token,
                        "pkce_verifier": verifier,
                        "pkce_challenge": challenge
                    }
                else:
                    logger.warning(f"OTP failed on IP {ip}: {otp_resp.status_code}")
                    
            except Exception as e:
                logger.warning(f"IP {ip} error: {str(e)}")
                continue
        
        raise Exception("All auth IPs failed - check network connectivity")
    
    def verify_otp(self, mobile, otp, csrf_token, pkce_verifier):
        """Verify OTP using working IP"""
        if not self.working_ip:
            # Try all IPs
            for ip in self.AUTH_IPS:
                try:
                    result = self._verify_on_ip(ip, mobile, otp, csrf_token, pkce_verifier)
                    if result:
                        self.working_ip = ip
                        return result
                except:
                    continue
            raise Exception("OTP verification failed on all IPs")
        
        # Use working IP
        return self._verify_on_ip(self.working_ip, mobile, otp, csrf_token, pkce_verifier)
    
    def _verify_on_ip(self, ip, mobile, otp, csrf_token, pkce_verifier):
        """Verify OTP on specific IP"""
        endpoint = self._get_endpoint(ip)
        
        verify_resp = self.session.post(
            f"{endpoint}/api/v1/auth/verify",
            json={
                "mobile": mobile,
                "otp": otp,
                "csrf_token": csrf_token,
                "code_verifier": pkce_verifier
            },
            headers={"Host": self.AUTH_HOST},
            timeout=10,
            verify=False
        )
        
        if verify_resp.status_code != 200:
            raise Exception(f"Verify failed: {verify_resp.status_code}")
        
        data = verify_resp.json()
        cookies = self.session.cookies.get_dict()
        
        return {
            "access_token": cookies.get('access_token'),
            "refresh_token": cookies.get('refresh_token'),
            "session_id": cookies.get('session_id'),
            "user_id": data.get('user_id'),
            "expires_at": time.time() + 86400,
            "cookies": cookies,
            "mobile": mobile
        }