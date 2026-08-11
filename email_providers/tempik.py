"""Tempik (tempmail.hafizhmuzani.my.id) 临时邮箱客户端。

Self-hosted 临时邮箱服务，通过 x-session-id 标识会话。
提供 create_mailbox + wait_for_code，与其它 provider 接口对齐。
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Optional, Tuple

from email_providers.common import extract_verification_code

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]

API_BASE_DEFAULT = "https://tempmail.hafizhmuzani.my.id"


def normalize_base(base_url: str = "") -> str:
    base = str(base_url or API_BASE_DEFAULT).strip().rstrip("/")
    return base or API_BASE_DEFAULT


def get_domains(http_get: HttpGet, base_url: str = "") -> list:
    base = normalize_base(base_url)
    resp = http_get(f"{base}/api/domains", timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("domains", "data", "items", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    base_url: str,
    domain: str = "",
    *,
    username: str = "",
) -> Tuple[str, str]:
    """创建 Tempik 收件箱，返回 (address, session_id)。

    session_id 作为后续拉取邮件的 x-session-id Bearer token。
    """
    base = normalize_base(base_url)
    domain = str(domain or "").strip().lstrip("@")
    if not domain:
        raise Exception("Tempik default domain 未配置")
    sess = http_post(f"{base}/api/session", timeout=15)
    sess.raise_for_status()
    session_id = (sess.json() or {}).get("sessionId", "")
    if not session_id:
        raise Exception(f"Tempik session 失败: {sess.text[:200]}")
    inbox = http_post(
        f"{base}/api/inboxes",
        json={"domain": domain},
        headers={"x-session-id": session_id},
        timeout=15,
    )
    inbox.raise_for_status()
    address = (inbox.json() or {}).get("address", "")
    if not address:
        raise Exception(f"Tempik inboxes 失败: {inbox.text[:200]}")
    return address, session_id


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    session_id: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    base = normalize_base(base_url)
    deadline = time.time() + timeout
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            resp = http_get(
                f"{base}/api/inboxes/{email}/messages",
                headers={"x-session-id": session_id},
                timeout=15,
            )
            resp.raise_for_status()
            messages = resp.json() or []
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Tempik 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Tempik 本轮邮件数量: {len(messages)}")
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            subject = str(msg.get("subject", "") or "")
            body = msg.get("body_text") or msg.get("body") or ""
            if not body and msg.get("body_html"):
                body = re.sub(r"<[^>]+>", " ", str(msg.get("body_html")))
            combined = f"{subject}\n{body}"
            if log_callback:
                log_callback(f"[Debug] Tempik 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Tempik 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Tempik 在 {timeout}s 内未收到验证码邮件")
