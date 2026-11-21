#!/usr/bin/env python3
"""Zero-dependency Python Email 6-Digit OTP Backend (Brevo HTTPS API + QQ SMTP fallback)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import time
import urllib.error
import urllib.request
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
OTP_TTL_SECONDS = 300  # 5 minutes


def get_secret() -> bytes:
    return os.environ.get("OTP_SECRET", "change-me-to-a-random-32-char-secret").encode("utf-8")


def sign_challenge(email: str, code: str, expires_at: int) -> str:
    """Create a stateless HMAC-SHA256 signed challenge token."""
    payload = f"{email.lower()}|{code}|{expires_at}".encode("utf-8")
    sig = hmac.new(get_secret(), payload, hashlib.sha256).hexdigest()
    raw = f"{email.lower()}|{expires_at}|{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def verify_challenge(email: str, code: str, token: str, now_ts: int | None = None) -> tuple[bool, str]:
    """Verify email + 6-digit code against the signed challenge token."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        tok_email, exp_str, tok_sig = decoded.split("|", 2)
        expires_at = int(exp_str)
    except (ValueError, UnicodeDecodeError):
        return False, "验证令牌无效，请重新获取验证码"

    current = int(time.time()) if now_ts is None else now_ts
    if current > expires_at:
        return False, "验证码已过期（有效期 5 分钟），请重新获取"
    if tok_email != email.strip().lower():
        return False, "邮箱与获取验证码时不一致"

    expected_payload = f"{tok_email}|{code.strip()}|{expires_at}".encode("utf-8")
    expected_sig = hmac.new(get_secret(), expected_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, tok_sig):
        return False, "6 位数字验证码不正确，请核对后重试"
    return True, "验证通过"


def build_email_html(code: str) -> str:
    return (
        "<div style='font-family:sans-serif;max-width:480px;margin:0 auto;padding:20px;"
        "border:1px solid #e2e8f0;border-radius:12px;'>"
        "<h2 style='color:#0f172a;margin-top:0;'>敏捷 DevOps 个人博客 · 邮箱注册验证码</h2>"
        "<p style='color:#475569;'>你正在注册或验证账号，本次 6 位数字验证码为：</p>"
        f"<div style='font-size:32px;font-weight:700;letter-spacing:6px;color:#1d4ed8;"
        f"background:#eff6ff;padding:14px 20px;border-radius:8px;text-align:center;'>{code}</div>"
        "<p style='color:#64748b;font-size:13px;margin-top:16px;'>验证码 5 分钟内有效，请勿泄露给他人。</p>"
        "</div>"
    )


def send_via_brevo_https(to_email: str, code: str) -> None:
    """Send 6-digit OTP email over HTTPS (Port 443) via Brevo Transactional Email API."""
    api_key = os.environ.get("BREVO_API_KEY", "").strip()
    sender_email = (
        os.environ.get("SENDER_EMAIL", "").strip()
        or os.environ.get("QQ_EMAIL", "").strip()
    )
    if not sender_email:
        raise RuntimeError("请设置环境变量 SENDER_EMAIL（在 Brevo 验证过的发件人邮箱）")

    payload = json.dumps(
        {
            "sender": {"name": "敏捷 DevOps 博客", "email": sender_email},
            "to": [{"email": to_email}],
            "subject": f"【个人博客】你的注册验证码：{code}",
            "htmlContent": build_email_html(code),
        },
        ensure_ascii=False,
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        method="POST",
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 201, 202):
                raise RuntimeError(f"Brevo API 返回异常状态码 {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Brevo API 错误 ({exc.code}): {detail}") from exc


def send_via_qq_smtp(to_email: str, code: str) -> None:
    """Fallback: Send via QQ Mail SSL SMTP (works locally or on paid hosts with port 465 open)."""
    qq_user = os.environ.get("QQ_EMAIL", "").strip()
    qq_auth = os.environ.get("QQ_SMTP_AUTH_CODE", "").strip()
    if not qq_user or not qq_auth:
        raise RuntimeError("未配置 BREVO_API_KEY，且未配置 QQ_EMAIL / QQ_SMTP_AUTH_CODE")

    msg = MIMEText(build_email_html(code), "html", "utf-8")
    msg["From"] = formataddr((str(Header("敏捷 DevOps 博客", "utf-8")), qq_user))
    msg["To"] = to_email
    msg["Subject"] = Header(f"【个人博客】你的注册验证码：{code}", "utf-8")

    with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=15) as server:
        server.login(qq_user, qq_auth)
        server.sendmail(qq_user, [to_email], msg.as_string())


def send_otp_email(to_email: str, code: str) -> None:
    if os.environ.get("BREVO_API_KEY", "").strip():
        send_via_brevo_https(to_email, code)
    else:
        send_via_qq_smtp(to_email, code)


class OtpHandler(BaseHTTPRequestHandler):
    """HTTP JSON API with CORS for /api/send-code and /api/verify-code."""

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", os.environ.get("CORS_ORIGIN", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self._send_json(200, {"ok": True})

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:
        provider = "brevo-https" if os.environ.get("BREVO_API_KEY", "").strip() else "qq-smtp"
        if self.path in ("/", "/api/health"):
            self._send_json(200, {"ok": True, "provider": provider})
        else:
            self._send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "请求 JSON 格式错误"})
            return

        if self.path == "/api/send-code":
            email = str(body.get("email", "")).strip().lower()
            if not EMAIL_RE.match(email):
                self._send_json(400, {"ok": False, "error": "请输入有效的电子邮箱地址"})
                return
            code = f"{secrets.randbelow(900000) + 100000}"
            expires_at = int(time.time()) + OTP_TTL_SECONDS
            try:
                send_otp_email(email, code)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"邮件发送失败：{exc}"})
                return
            token = sign_challenge(email, code, expires_at)
            self._send_json(200, {"ok": True, "challengeToken": token, "expiresIn": OTP_TTL_SECONDS})
            return

        if self.path == "/api/verify-code":
            email = str(body.get("email", "")).strip().lower()
            code = str(body.get("code", "")).strip()
            token = str(body.get("challengeToken", "")).strip()
            ok, msg = verify_challenge(email, code, token)
            self._send_json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        self._send_json(404, {"ok": False, "error": "Unknown endpoint"})


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8787"))
    print(f"[OTP-Backend] Listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), OtpHandler).serve_forever()


if __name__ == "__main__":
    main()