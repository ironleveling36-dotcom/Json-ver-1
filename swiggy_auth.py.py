# swiggy_auth.py - Fixed DNS + Multiple Endpoint Fallback
import requests
import json
import time
import secrets
import hashlib
import base64
import os
import logging
import socket
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class SwiggyAuth:
    """Swiggy OAuth PKCE - DNS resilient with fallback endpoints"""
    
    # Primary and fallback endpoints
    AUTH_ENDPOINTS = [
        "https://account.swiggy.com",
        "https://auth.swiggy.com",
        "https://api.swiggy.com/auth",
        "https://identity.swiggy.com"
    ]
    
    API_ENDPOINTS = [
        "https://mcp.swiggy.com",
        "https://api.swiggy.com/mcp"
    ]
    
    def __init__(self, state_dir="/tmp/swiggy", proxy_url=None):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.proxy_url = proxy_url
        self.session = self._create_session()
        self.auth_url = self._discover_auth_endpoint()
        
    def _create_session(self):
        """Create session with retry strategy and DNS fallback"""
        session = requests.Session()
        
        # Retry strategy
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # User agent to mimic mobile app
        session.headers.update({
            'User-Agent': 'Swiggy/4.12.0 (Android; 13)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Proxy configuration
        if self.proxy_url:
            session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
        
        return session
    
    def _discover_auth_endpoint(self):
        """Find working auth endpoint with DNS fallback"""
        for endpoint in self.AUTH_ENDPOINTS:
            try:
                # Attempt to resolve DNS
                hostname = endpoint.replace('https://', '').replace('http://', '').split('/')[0]
                socket.gethostbyname(hostname)
                
                # Test endpoint
                test_resp = self.session.get(
                    f"{endpoint}/api/v1/auth/init",
                    params={"mobile": "+919999999999"},
                    timeout=5,
                    verify=True
                )
                if test_resp.status_code < 500:
                    logger.info(f"✅ Auth endpoint discovered: {endpoint}")
                    return endpoint
            except Exception as e:
                logger.warning(f"Endpoint {endpoint} failed: {str(e)}")
                continue
        
        # Fallback to primary even if unresolved (some VPS have DNS issues)
        logger.warning("⚠️ All endpoints failed, using primary with IP fallback")
        return "https://account.swiggy.com"
    
    def init_session(self, mobile):
        """Initialize auth and get CSRF token with DNS fallback"""
        try:
            # Use IP directly if DNS fails - hardcoded fallback IPs
            endpoints_to_try = [
                self.auth_url,
                "https://18.218.123.45",  # Fallback IP (replace with actual Swiggy IP)
                "https://13.126.23.78"    # Another fallback
            ]
            
            for endpoint in endpoints_to_try:
                try:
                    # Start session
                    init_resp = self.session.get(
                        f"{endpoint}/api/v1/auth/init",
                        params={"mobile": mobile},
                        timeout=10,
                        verify=False  # Required for IP-based requests
                    )
                    init_resp.raise_for_status()
                    
                    # Extract CSRF
                    csrf_token = self.session.cookies.get('csrf_token')
                    if csrf_token:
                        self.auth_url = endpoint  # Cache working endpoint
                        break
                except Exception:
                    continue
            else:
                raise Exception("All auth endpoints failed")
            
            # Generate PKCE
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).decode().rstrip('=')
            
            # Request OTP
            otp_resp = self.session.post(
                f"{self.auth_url}/api/v1/auth/otp",
                json={
                    "mobile": mobile,
                    "csrf_token": csrf_token,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256"
                },
                timeout=10
            )
            otp_resp.raise_for_status()
            
            return {
                "csrf_token": csrf_token,
                "pkce_verifier": verifier,
                "pkce_challenge": challenge,
                "endpoint": self.auth_url
            }
            
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Connection error: {str(e)}. Check proxy or network.")
        except Exception as e:
            raise Exception(f"OTP request failed: {str(e)}")
    
    def verify_otp(self, mobile, otp, csrf_token, pkce_verifier):
        """Verify OTP and return tokens"""
        try:
            verify_resp = self.session.post(
                f"{self.auth_url}/api/v1/auth/verify",
                json={
                    "mobile": mobile,
                    "otp": otp,
                    "csrf_token": csrf_token,
                    "code_verifier": pkce_verifier
                },
                timeout=10
            )
            verify_resp.raise_for_status()
            
            data = verify_resp.json()
            cookies = self.session.cookies.get_dict()
            
            return {
                "access_token": cookies.get('access_token'),
                "refresh_token": cookies.get('refresh_token'),
                "session_id": cookies.get('session_id'),
                "user_id": data.get('user_id'),
                "expires_at": time.time() + 86400,
                "cookies": cookies,
                "mobile": mobile,
                "endpoint_used": self.auth_url
            }
        except Exception as e:
            raise Exception(f"OTP verification failed: {str(e)}")
    
    def get_working_endpoint(self):
        """Return currently working endpoint"""
        return self.auth_url