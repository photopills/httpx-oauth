import re
import json

import pytest
import respx
from httpx import Response

from httpx_oauth.clients.apple import (
    AppleOAuth2,
    ACCESS_TOKEN_ENDPOINT,
    JWK_ENDPOINT,
    JWT_SIGNED_AUDIENCE,
    SCOPES_SEPARATOR,
    AppleKeyIDNotFound,
)
from httpx_oauth.errors import GetIdEmailError

# Faked Apple OAuth
payload = {
    "client_id": "CLIENT_ID",
    "team": "TEAM",
    "key": "KEY",
    "client_secret": """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHTTmAHApdRSJRUXk5nA1rXjBNw6wHJEFeCtJdbIagFloAoGCCqGSM49
AwEHoUQDQgAEpsoqi4btr3Q3PeHt7GdJisLHe6xWY0CRGXkRJa3EuMtic53w5Cv9
WWnLVDXL1V7yEYW2PwS0u2Y3SL3Ns24wHw==
-----END EC PRIVATE KEY-----""",
}

client = AppleOAuth2(**payload)


def test_apple_oauth2():
    assert client.authorize_endpoint == "https://appleid.apple.com/auth/authorize"
    assert client.access_token_endpoint == "https://appleid.apple.com/auth/token"
    assert JWK_ENDPOINT == "https://appleid.apple.com/auth/keys"
    assert JWT_SIGNED_AUDIENCE == "https://appleid.apple.com"
    assert SCOPES_SEPARATOR == "%20"

    assert client.base_scopes == [
        "email",
        "name",
    ]
    assert client.name == "apple"


get_apple_auth_keys_response = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "eXaunmL",
            "use": "sig",
            "alg": "RS256",
            "n": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtuwJFrdeAQ1iZBA3wo3RazaGaDUpw1D5rUEtoo+BmftYhz53qbRvz2094p+kKFuXXxqfGKMbJFmqKRsy45npm+wuG/fAy9MDwEwp7PpQww1Gee/g3h8NTggWo1Nup3lSBGomREIN/R/IELTiajVMIgTlMmYAGpn73whiZGJo5qwuorltuNhKCSpCFLAxgO0tF/30wnnf7Lqq4Lf8oFuFjqTwUGagBZb4SskTw3cfsgbLSVfLuaii4SkcmydPXOWwAnskHCD070xy8E6V+7W0TOaThv5kbBS4hUBX9IrfEnpc+rlufVdFrSJsVfpNlO1es7vwCUggSWoLVb22S8rVpwIDAQAB",
            "e": "AQAB",
        },
        {
            "kty": "RSA",
            "kid": "AIDOPK1",
            "use": "sig",
            "alg": "RS256",
            "n": "lxrwmuYSAsTfn-lUu4goZSXBD9ackM9OJuwUVQHmbZo6GW4Fu_auUdN5zI7Y1dEDfgt7m7QXWbHuMD01HLnD4eRtY-RNwCWdjNfEaY_esUPY3OVMrNDI15Ns13xspWS3q-13kdGv9jHI28P87RvMpjz_JCpQ5IM44oSyRnYtVJO-320SB8E2Bw92pmrenbp67KRUzTEVfGU4-obP5RZ09OxvCr1io4KJvEOjDJuuoClF66AT72WymtoMdwzUmhINjR0XSqK6H0MdWsjw7ysyd_JhmqX5CAaT9Pgi0J8lU_pcl215oANqjy7Ob-VMhug9eGyxAWVfu_1u6QJKePlE-w",
            "e": "AQAB",
        },
    ]
}

get_access_token_response = {
    "access_token": "adg61...67Or9",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "rca7...lABoQ",
    "id_token": "eyJraWQiOiJBSURPUEsxIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLnRlbmNlbnQucXFtdXNpY2JhYnkuZCIsImV4cCI6MTU3MDYxNTU3NywiaWF0IjoxNTcwNjE0OTc3LCJzdWIiOiIwMDA2NTcuNjY1NjJkM2IxMWJjNDAzMDk5YjFjZGI0OTQ3YzFkM2MuMTE0MiIsImF0X2hhc2giOiJibFQ3UTFNMDF1NW12Y0ZVZ1JIZGR3IiwiYXV0aF90aW1lIjoxNTcwNjE0OTI0fQ.TXpunnl6hlJs8C9_W7k-LeJ3Lm_otBeLoJxwe1C2oufKmMWxlANu0KI2-LnTcHYx23npMY3swk4fM46W5Vt9ursllz27P4zR8H1eoZ2Tj-3O3rTz8lqC1uI-mMo_a6VxqXvNmqenre5S0CyaUHAI1_Um9798b4ehduJqDtYVYIbftYIpiXBAW-vGjEbBnjWkHw_7HmjEWrsc0vfPhHGXyUMFmon4VhMBzzY2Nq0LIF4NP9Aa_9dyTzdEaqNfPjdSbFCVaJcTI_rxrIbooh18UbdowsFJtnLKsTZ7ePYtz3uBIaWUaiwJI1oU6ZeAb6uAzHl7TV2DdB9UkHDJe960hg",
}


class TestAppleGetAccessURL:
    @pytest.mark.asyncio
    async def test_success(self, get_respx_call_args):
        authorization_url = await client.get_authorization_url(
            redirect_uri="redirect_uri"
        )

        assert (
            SCOPES_SEPARATOR.join(client.base_scopes) in authorization_url
        ), "Scopes should be generated with the expected separator"


class TestAppleVerifyJWKSignature:
    @pytest.mark.asyncio
    @respx.mock
    async def test_success(self, get_respx_call_args):
        """
        If requested kid exist, should be returned
        """
        request = respx.get(JWK_ENDPOINT).mock(
            return_value=Response(200, json=get_apple_auth_keys_response)
        )

        mocked_key = get_apple_auth_keys_response["keys"][0]

        jwk_string = await client.get_apple_jwk(mocked_key["kid"])
        jwk = json.loads(jwk_string)
        (
            url,
            headers,
            content,
        ) = await get_respx_call_args(request)

        assert mocked_key == jwk

    @pytest.mark.asyncio
    @respx.mock
    async def test_error(self, get_respx_call_args):
        """
        If requested kid does not exist, should raise `AppleKeyIDNotFound`
        """

        request = respx.get(JWK_ENDPOINT).mock(
            return_value=Response(200, json=get_apple_auth_keys_response)
        )

        mocked_key = get_apple_auth_keys_response["keys"][0]

        with pytest.raises(AppleKeyIDNotFound) as excinfo:
            jwk_string = await client.get_apple_jwk("THIS_KID_DOES_NOT_EXIST")


class TestAppleGetAccessToken:
    @pytest.mark.asyncio
    @respx.mock
    async def test_success(
        self,
    ):
        respx.post(ACCESS_TOKEN_ENDPOINT).mock(
            return_value=Response(200, json=get_access_token_response)
        )

        result = await client.get_access_token("TOKEN", "redirect")

        assert result["access_token"] == get_access_token_response["access_token"]
        assert result["id_token"] == get_access_token_response["id_token"]

        return result


class TestAppleGetIDEmail:
    @pytest.mark.asyncio
    @respx.mock
    async def test_expired_signature(
        self,
    ):

        result = get_access_token_response

        respx.get(JWK_ENDPOINT).mock(
            return_value=Response(200, json=get_apple_auth_keys_response)
        )

        # Example id_token signature has been expired, so it should raise just for expiration
        with pytest.raises(GetIdEmailError) as excinfo:
            data = await client.get_id_email(result)
            assert excinfo.value.args[0] == "Signature has expired"

    @pytest.mark.asyncio
    @respx.mock
    async def test_without_id_token(self):
        result = get_access_token_response

        del result["id_token"]

        respx.get(JWK_ENDPOINT).mock(
            return_value=Response(200, json=get_apple_auth_keys_response)
        )

        with pytest.raises(GetIdEmailError) as excinfo:
            data = await client.get_id_email(result)
        assert excinfo.value.args[0] == "Missing id_token parameter"
