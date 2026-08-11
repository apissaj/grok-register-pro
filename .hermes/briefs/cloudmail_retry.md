# Task: CloudMail auth resilience

## File
`email_providers/cloudmail.py` only

## Goal
Fix `CloudMail 添加邮箱失败: 身份认证失效,请重新登录` by auto re-login + retry.

## Requirements
1. Add helper `_is_auth_error(exc_or_msg) -> bool` matching: 身份认证, 重新登录, unauthorized, 401, token, 鉴权, invalid, expired (case-insensitive).
2. Cache admin JWT like public token (`_admin_jwt`, lock) with `get_admin_jwt(..., force_refresh=False)`.
3. Change `add_address` to:
   - use cached JWT first
   - on auth failure: force refresh JWT, retry add once
   - log via print: `[CloudMail] auth expired, re-login and retry...`
4. Same for `delete_address` (one retry on auth fail).
5. `create_mailbox`: if `add_address` fails with auth error after internal retry, call `reset_runtime_state()` or force clear tokens and retry create once more.
6. Keep existing public token refresh in `wait_for_code`.
7. Do not break existing function signatures used by callers (kwargs optional OK).
8. `python -m py_compile email_providers/cloudmail.py`

## Report
Write to `.hermes/briefs/cloudmail_retry.report.md`: summary, files changed, compile result.