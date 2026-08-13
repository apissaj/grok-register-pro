"""Sync-batch probe proxies from the pool and persist results.

Runs INLINE (not a daemon thread) so results are written before process exit.
"""
import sys, time, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webui import proxy_store as ps

def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    pool = ps.read_proxy_pool()
    # only test unknown/enabled ones
    items = [i for i in pool['items'] if i['enabled']]
    items = items[:limit]
    print(f"probing {len(items)} proxies...", flush=True)

    start = time.time()
    healthy = 0
    failed = 0
    for n, it in enumerate(items, 1):
        url = it.get('url') or it.get('display_url', '')
        if not url:
            continue
        try:
            res = ps.probe_proxy(url, timeout=6.0)
        except Exception as exc:
            res = {"ok": False, "error": str(exc)[:120]}
        ps._apply_probe_result(it['id'], res)
        if res.get('ok'):
            healthy += 1
        else:
            failed += 1
        if n % 25 == 0 or res.get('ok'):
            print(f"  [{n}/{len(items)}] {'OK' if res.get('ok') else 'fail'} "
                  f"{it.get('host','?')}:{it.get('port','?')} {res.get('exit_ip','')}", flush=True)

    print(f"\nDONE in {time.time()-start:.0f}s: healthy={healthy} failed={failed}", flush=True)

if __name__ == '__main__':
    main()