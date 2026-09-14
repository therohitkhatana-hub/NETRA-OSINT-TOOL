"""
Account presence module for NETRA — OWN IMPLEMENTATION, no third-party OSINT library.
Checks platform signup/recovery flows for email presence across major platforms.
"""
import asyncio
import re
import random
import httpx
from db import Finding

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


def _ua():
    return random.choice(USER_AGENTS)


async def _check_github(email: str, client: httpx.AsyncClient) -> tuple[str, bool | None, str]:
    try:
        page = await client.get("https://github.com/join", headers={"User-Agent": _ua()})
        token_match = re.search(
            r'<auto-check src="/signup_check/email"[\s\S]*?value="([^"]+)"', page.text
        )
        if not token_match:
            return "github", None, "could not extract CSRF token (page structure may have changed)"
        token = token_match.group(1)
        resp = await client.post(
            "https://github.com/signup_check/email",
            data={"value": email, "authenticity_token": token},
            headers={"User-Agent": _ua()},
        )
        if resp.status_code == 422:
            return "github", True, "signup-check endpoint returned 422 (email taken)"
        if resp.status_code == 200:
            return "github", False, "signup-check endpoint returned 200 (email available)"
        return "github", None, f"unexpected status {resp.status_code}"
    except Exception as e:
        return "github", None, f"request failed: {e}"


async def _check_spotify(email: str, client: httpx.AsyncClient) -> tuple[str, bool | None, str]:
    try:
        resp = await client.get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": "1", "email": email},
            headers={"User-Agent": _ua()},
        )
        status = resp.json().get("status")
        if status == 200 or status == 20:
            return "spotify", True, "signup API status=20 (email taken)"
        if status == 1:
            return "spotify", False, "signup API status=1 (email available)"
        return "spotify", None, f"unexpected API status {status}"
    except Exception as e:
        return "spotify", None, f"request failed: {e}"


async def _check_imgur(email: str, client: httpx.AsyncClient) -> tuple[str, bool | None, str]:
    try:
        await client.get("https://imgur.com/register?redirect=%2Fuser", headers={"User-Agent": _ua()})
        resp = await client.post(
            "https://imgur.com/signin/ajax_email_available",
            data={"email": email},
            headers={"User-Agent": _ua(), "X-Requested-With": "XMLHttpRequest"},
        )
        if resp.status_code != 200:
            return "imgur", None, f"unexpected status {resp.status_code}"
        data = resp.json()
        available = data.get("data", {}).get("available", None)
        if available is None:
            return "imgur", None, "unexpected response shape"
        return "imgur", (not available), f"AJAX endpoint reports available={available}"
    except Exception as e:
        return "imgur", None, f"request failed: {e}"


async def _check_adobe(email: str, client: httpx.AsyncClient) -> tuple[str, bool | None, str]:
    try:
        resp = await client.post(
            "https://auth.services.adobe.com/signin/v1/authenticationstate",
            headers={
                "User-Agent": _ua(),
                "X-IMS-CLIENTID": "adobedotcom2",
                "Content-Type": "application/json;charset=utf-8",
            },
            content=f'{{"username":"{email}","accountType":"individual"}}',
        )
        data = resp.json()
        if "errorCode" in data:
            return "adobe", False, "authentication-state step rejected email (not registered)"

        state_id = data.get("id")
        challenge_resp = await client.get(
            "https://auth.services.adobe.com/signin/v2/challenges",
            headers={
                "User-Agent": _ua(),
                "X-IMS-CLIENTID": "adobedotcom2",
                "X-IMS-Authentication-State": state_id,
            },
            params={"purpose": "passwordRecovery"},
        )
        if challenge_resp.status_code == 200:
            return "adobe", True, "password-recovery challenge step reached (email registered)"
        return "adobe", None, f"unexpected challenge status {challenge_resp.status_code}"
    except Exception as e:
        return "adobe", None, f"request failed: {e}"


async def _check_instagram(email: str, client: httpx.AsyncClient) -> tuple[str, bool | None, str]:
    try:
        headers = {"User-Agent": _ua(), "Origin": "https://www.instagram.com"}
        page = await client.get("https://www.instagram.com/accounts/emailsignup/", headers=headers)
        token_match = re.search(r'"csrf_token":"([^"]+)"', page.text)
        if not token_match:
            return "instagram", None, "could not extract CSRF token (page structure may have changed)"
        headers["x-csrftoken"] = token_match.group(1)

        resp = await client.post(
            "https://www.instagram.com/accounts/web_create_ajax/attempt/",
            data={"email": email, "username": "", "first_name": "", "opt_into_one_tap": "false"},
            headers=headers,
        )
        data = resp.json()
        if data.get("status") == "fail":
            return "instagram", None, "rate-limited or blocked by Instagram"
        errors = data.get("errors", {})
        if "email" in errors and errors["email"] and errors["email"][0].get("code") == "email_is_taken":
            return "instagram", True, "signup endpoint reports email_is_taken"
        return "instagram", False, "signup endpoint accepted email as available"
    except Exception as e:
        return "instagram", None, f"request failed: {e}"


CHECKERS = [_check_github, _check_spotify, _check_imgur, _check_adobe, _check_instagram]


def check_account_presence(identifier: str) -> list[Finding]:
    if "@" not in identifier:
        return []

    try:
        results = asyncio.run(_run_all(identifier))
    except Exception as e:
        return [Finding(identifier, "account_presence (own impl)", f"platform checks failed to run: {e}", 0.0, "error")]

    findings = []
    for platform, exists, detail in results:
        if exists is True:
            findings.append(Finding(
                identifier, "account_presence (own impl)",
                f"account found on {platform} ({detail})",
                0.7, f"own_check:{platform}",
            ))
        elif exists is False:
            findings.append(Finding(
                identifier, "account_presence (own impl)",
                f"no account found on {platform} ({detail})",
                0.35, f"own_check:{platform}",
            ))
        else:
            findings.append(Finding(
                identifier, "account_presence (own impl)",
                f"{platform} check inconclusive: {detail}",
                0.0, f"own_check:{platform}",
            ))

    return findings


async def _run_all(email: str) -> list[tuple[str, bool | None, str]]:
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
        tasks = [checker(email, client) for checker in CHECKERS]
        return await asyncio.gather(*tasks)
