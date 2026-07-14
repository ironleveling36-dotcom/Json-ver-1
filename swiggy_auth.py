# swiggy_auth.py - Swiggy OAuth PKCE implementation
import os
import time
import secrets
import hashlib
import base64
import requests


class SwiggyAuth:
    OAUTH_URL = "https://account.swiggy.com"
    API_URL = "https://mcp.swiggy.com"

    def __init__(self, state_dir="/tmp/swiggy"):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0 Safari/537.36"
                ),
                "Accept": "application/json",
            }
        )

    def init_session(self, mobile: str):
        init_resp = self.session.get(
            f"{self.OAUTH_URL}/api/v1/auth/init", params={"mobile": mobile}, timeout=20
        )
        init_resp.raise_for_status()

        csrf_token = self.session.cookies.get("csrf_token")
        if not csrf_token:
            raise Exception("CSRF token not found")

        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        otp_resp = self.session.post(
            f"{self.OAUTH_URL}/api/v1/auth/otp",
            json={
                "mobile": mobile,
                "csrf_token": csrf_token,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            timeout=20,
        )
        otp_resp.raise_for_status()

        return {
            "csrf_token": csrf_token,
            "pkce_verifier": verifier,
            "pkce_challenge": challenge,
        }

    def verify_otp(self, mobile: str, otp: str, csrf_token: str, pkce_verifier: str):
        verify_resp = self.session.post(
            f"{self.OAUTH_URL}/api/v1/auth/verify",
            json={
                "mobile": mobile,
                "otp": otp,
                "csrf_token": csrf_token,
                "code_verifier": pkce_verifier,
            },
            timeout=20,
        )
        verify_resp.raise_for_status()

        data = verify_resp.json() if verify_resp.content else {}
        cookies = self.session.cookies.get_dict()

        return {
            "access_token": cookies.get("access_token"),
            "refresh_token": cookies.get("refresh_token"),
            "session_id": cookies.get("session_id"),
            "user_id": data.get("user_id"),
            "expires_at": time.time() + 86400,
            "cookies": cookies,
            "mobile": mobile,
        }
