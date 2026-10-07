"""الفاحص: يجرّب كل منظومة ويكتب حالتها في data/status.json، وبعدين يعاود بناء الموقع.

يشتغل كل 5 دقايق عن طريق systemd timer (شوف deploy/).

قواعد الحماية في الفاحص:
- يتصل بس بالروابط اللي عدّت التحقق في safety.check_url.
- لو المنظومة حوّلت (redirect) لنطاق مش رسمي: ما يتبعهاش، ويحط الحالة "suspicious"
  والموقع يخفي زر الدخول تلقائياً لين نراجعوها. هذا يحمي الزوار لو نطاق حكومي انسرق أو انتهى.
- مهلة لكل طلب، وما يقراش أكثر من 64KB من أي رد (ما يتعطلش بردود ضخمة).
- ما يحكمش إن المنظومة "واقفة" إلا بعد فشلتين ورا بعض (عشان ما نخوفوش الناس على غلطة وحدة).
- كتابة الملف ذرية (ملف مؤقت ثم استبدال) + قفل يمنع تشغيل نسختين مع بعض.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import config
from .data import DataError, load_site
from .safety import host_allowed

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 15
MAX_BYTES = 64 * 1024
MAX_REDIRECTS = 5
FAILS_BEFORE_DOWN = 2
USER_AGENT = f"ManzumatiChecker/1.0 (+{config.SITE_URL}/about.html)"


class Suspicious(Exception):
    """الرابط حوّل لمكان مش رسمي."""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, extra_hosts: tuple[str, ...]):
        super().__init__()
        self.extra_hosts = extra_hosts

    def _check(self, base: str, newurl: str) -> str:
        target = urljoin(base, newurl)
        parts = urlsplit(target)
        host = parts.hostname or ""
        if parts.scheme not in ("http", "https") or parts.username or parts.password \
                or not host_allowed(host, self.extra_hosts):
            raise Suspicious(target[:200])
        return target

    # نفحصو وجهة التحويل قبل أي شيء ثاني (حتى قبل فحوصات مكتبة بايثون نفسها)
    def http_error_302(self, req, fp, code, msg, headers):
        loc = headers.get("location") or headers.get("uri")
        if loc:
            self._check(req.full_url, loc)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = self._check(req.full_url, newurl)
        return super().redirect_request(req, fp, code, msg, headers, target)


# 404 و 410: الصفحة نفسها مش موجودة، يعني المواطن يلقى صفحة خطأ → نعتبروها واقفة.
# باقي أخطاء 4xx (مثلاً 401 و 403): السيرفر حي لكن يطلب دخول أو يقفل في وجه البرامج الآلية،
# والمواطن من المتصفح غالباً يدخل عادي → نعتبروها شغالة.
# 5xx: عطل في السيرفر → واقفة.
NOT_FOUND = {404, 410}


def _classify(code: int) -> str:
    if code in NOT_FOUND or code >= 500 or code < 400:
        return "fail"
    return "ok"


def probe(url: str, extra_hosts: tuple[str, ...] = ()) -> str:
    """يرجع: ok / fail / suspicious."""
    ctx = ssl.create_default_context()           # التحقق من الشهادة مفعّل دائماً
    opener = urllib.request.build_opener(
        SafeRedirect(extra_hosts),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.ProxyHandler({}),         # ما نمرّوش عن طريق أي بروكسي من متغيرات البيئة
    )
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "identity"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            resp.read(MAX_BYTES)
            return "ok" if resp.status < 400 else _classify(resp.status)
    except Suspicious:
        return "suspicious"
    except urllib.error.HTTPError as e:
        # 4xx معناها السيرفر حي ويرد (مثلاً يطلب تسجيل دخول)، 5xx معناها عطل
        # 3xx هنا معناها تحويلات بلا نهاية أو تحويل مكسور: نعتبروها عطل
        return _classify(e.code)
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError, OSError):
        return "fail"
    except Exception:
        return "fail"


def next_state(prev: dict, result: str, now: str) -> dict:
    fails = prev.get("fails", 0) if isinstance(prev.get("fails"), int) else 0
    if result == "suspicious":
        return {"state": "suspicious", "checked_at": now, "source": "checker", "fails": 0}
    if result == "ok":
        return {"state": "up", "checked_at": now, "source": "checker", "fails": 0}
    fails += 1
    state = "down" if fails >= FAILS_BEFORE_DOWN else prev.get("state", "up")
    if state not in ("up", "down"):
        state = "up" if fails < FAILS_BEFORE_DOWN else "down"
    return {"state": state, "checked_at": now, "source": "checker", "fails": fails}


def write_atomic(path: Path, obj: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".status-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def run(data_dir: Path, *, extra_hosts: tuple[str, ...] = (), allow_http: bool = False, workers: int = 8) -> dict:
    site = load_site(data_dir, extra_hosts=extra_hosts, allow_http=allow_http)
    status_path = data_dir / "status.json"
    try:
        old = json.loads(status_path.read_text(encoding="utf-8"))
        if not isinstance(old, dict):
            old = {}
    except (FileNotFoundError, json.JSONDecodeError):
        old = {}

    targets = site.visible()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda s: probe(s.safe_url, extra_hosts), targets))

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    new: dict = {}
    for s, r in zip(targets, results):
        prev = old.get(s.id) if isinstance(old.get(s.id), dict) else {}
        new[s.id] = next_state(prev, r, now)
    write_atomic(status_path, new)
    return new


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="فحص حالة المنظومات")
    ap.add_argument("--data", type=Path, default=ROOT / "data")
    ap.add_argument("--build", type=Path, help="بعد الفحص ابني الموقع في هذا المجلد")
    args = ap.parse_args(argv)

    lock_path = args.data / ".checker.lock"
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("فحص ثاني شغال توا، نطلعو.", file=sys.stderr)
            return 0
        try:
            res = run(args.data)
        except DataError as e:
            print(f"الفحص توقف: {e}", file=sys.stderr)
            return 1
        counts: dict[str, int] = {}
        for v in res.values():
            counts[v["state"]] = counts.get(v["state"], 0) + 1
        print("نتيجة الفحص:", counts)
        if args.build:
            from .build import build
            build(args.build, args.data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
