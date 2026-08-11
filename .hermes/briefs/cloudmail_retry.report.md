# CloudMail retry resilience — report

## Summary

Fixed `CloudMail 添加邮箱失败: 身份认证失效,请重新登录` by caching admin JWT and auto re-login + single retry on auth failures.

## Changes (`email_providers/cloudmail.py` only)

1. **`_is_auth_error(exc_or_msg) -> bool`**  
   Matches (case-insensitive): 身份认证, 重新登录, unauthorized, 401, token, 鉴权, invalid, expired.

2. **Admin JWT cache** (mirrors public token pattern)  
   - Globals: `_admin_jwt`, `_admin_jwt_config`, `_admin_jwt_lock`  
   - **`get_admin_jwt(..., force_refresh=False)`** — login once, reuse; force re-login when needed  
   - **`reset_runtime_state()`** also clears admin JWT cache

3. **`add_address`**  
   - Uses cached JWT first  
   - On auth error: log `[CloudMail] auth expired, re-login and retry...`, `force_refresh=True`, retry add once

4. **`delete_address`**  
   - Same one-retry-on-auth-fail path

5. **`create_mailbox`**  
   - If `add_address` still fails with auth error after its internal retry:  
     `reset_runtime_state()` + one full recreate attempt

6. **Unchanged**  
   - Public token refresh in `wait_for_code`  
   - Existing function signatures (callers unaffected)

## Compile

```text
python -m py_compile email_providers/cloudmail.py
→ COMPILE_OK (exit 0)
```

## Files changed

| File | Action |
|------|--------|
| `email_providers/cloudmail.py` | Modified |
| `.hermes/briefs/cloudmail_retry.report.md` | This report |

No commit (per task).
