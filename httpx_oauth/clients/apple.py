import time

from os import replace
from typing import Any, Dict, Optional, Tuple, cast, TypeVar
from urllib.parse import urlencode
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError
import jwt
import httpx
import json
from httpx_oauth.errors import GetIdEmailError
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token, GetAccessTokenError

JWK_ENDPOINT = "https://appleid.apple.com/auth/keys"
JWT_SIGNED_AUDIENCE = "https://appleid.apple.com"
JWT_SIGNED_TTL_SEC = 6 * 30 * 24 * 60 * 60

AUTHORIZE_ENDPOINT = "https://appleid.apple.com/auth/authorize"
ACCESS_TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token"
BASE_SCOPES = ["email", "name"]

# TODO: Improve Exception
AuthFailed = Exception


class GetLongLivedAccessTokenError(Exception):
    pass


T = TypeVar("T")


class AppleOAuth2(BaseOAuth2[Dict[str, Any]]):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        client_team: str,
        client_key: str,
        name: str = "apple",
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorize_endpoint=AUTHORIZE_ENDPOINT,
            access_token_endpoint=ACCESS_TOKEN_ENDPOINT,
            name=name,
            base_scopes=BASE_SCOPES,
        )
        self.client_team = client_team
        self.client_key = client_key

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str = None,
        scope: Optional[list[str]] = BASE_SCOPES,
        extras_params: Optional[T] = {},
    ) -> str:
        url = await super().get_authorization_url(
            redirect_uri,
            state,
            scope,
            extras_params={
                **extras_params,
                # "response_type": "code+id_token",
                "response_type": "code",
                "response_mode": "form_post",
            },
        )
        # Ensure that
        return url

    async def get_id_email(self, token: str) -> Tuple[str, str]:
        decoded = await self.decode_id_token(token.get("id_token"))
        return decoded.get("sub"), decoded.get("email")

    async def decode_id_token(self, id_token):
        """
        Decode and validate JWT token from apple and return payload including
        user data.
        """
        if not id_token:
            raise AuthFailed(self, "Missing id_token parameter")

        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            public_key = RSAAlgorithm.from_jwk(await self.get_apple_jwk(kid))
            decoded = jwt.decode(
                id_token,
                key=public_key,
                audience=self.client_id,
                algorithms=["RS256"],
            )
        except PyJWTError:
            raise AuthFailed(self, "Token validation failed")

        return decoded

    async def get_apple_jwk(self, kid=None):
        """
        Return requested Apple public key or all available.
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                JWK_ENDPOINT,
                headers=self.request_headers,
            )

            keys = response.json().get("keys")

        if not isinstance(keys, list) or not keys:
            raise AuthFailed(self, "Invalid jwk response")

        if kid:
            return json.dumps([key for key in keys if key["kid"] == kid][0])
        else:
            return (json.dumps(key) for key in keys)

    async def get_access_token(
        self, code: str, redirect_uri: str, client_id: Optional[str] = None
    ):
        """
        It requests an access_token following
        https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens  # noqa
        """

        self.request_headers["content-type"] = "application/x-www-form-urlencoded"
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.access_token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id or self.client_id,
                    "client_secret": self.client_secret_jwt,
                },
                headers=self.request_headers
                | {"content-type": "application/x-www-form-urlencoded"},
            )
            data = cast(Dict[str, Any], response.json())

            if response.status_code == 400:
                raise GetAccessTokenError(data)

            return OAuth2Token(data)

    @property
    def client_secret_jwt(self):
        """
        Provide an encoded client secret JWT
        """

        now = int(time.time())
        client_id = self.client_id
        team_id = self.client_team
        key_id = self.client_key
        private_key = self.client_secret

        headers = {"kid": key_id}
        payload = {
            "iss": team_id,
            "iat": now,
            "exp": now + JWT_SIGNED_TTL_SEC,
            "aud": JWT_SIGNED_AUDIENCE,
            "sub": client_id,
        }

        return jwt.encode(
            payload,
            key=private_key,
            algorithm="ES256",
            headers=headers,
        )
