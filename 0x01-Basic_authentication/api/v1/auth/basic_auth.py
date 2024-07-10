#!/usr/bin/env python3
"""Basic auth"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication cls"""
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header"""
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            fld_mtch = re.fullmatch(pattern, authorization_header.strip())
            if fld_mtch is not None:
                return fld_mtch.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes a base64-encoded"""
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authz"""
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            fld_mtch = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if fld_mtch is not None:
                user = fld_mtch.group('user')
                password = fld_mtch.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Retrieves a user based on the user's auth"""
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a req"""
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
