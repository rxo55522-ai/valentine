"""اختبارات الحماية. كل اختبار يجرب هجمة معروفة ويتأكد إنها ما تعداش.

التشغيل:  python3 -m unittest -v tests.test_security
"""
from __future__ import annotations

import http.server
from html.parser import HTMLParser
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from manzumati import build as B
from manzumati import checker as C
from manzumati import config
from manzumati.data import DataError, load_site
from manzumati.safety import UnsafeURL, check_url

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


class TagScan(HTMLParser):
    """يقرا الصفحة زي ما يقراها المتصفح ويجمع كل الوسوم وخصائصها الحقيقية."""

    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, {k: (v or "") for k, v in attrs}))

    handle_startendtag = handle_starttag

    def problems(self) -> list[str]:
        bad = []
        for tag, attrs in self.tags:
            if tag == "script" and "src" not in attrs:
                bad.append("سكربت داخل الصفحة")
            if tag in ("style", "iframe", "object", "embed", "base", "form") and not (tag == "form" and attrs.get("method") == "get"):
                bad.append(f"وسم ممنوع <{tag}>")
            for k, v in attrs.items():
                if k.startswith("on"):
                    bad.append(f"خاصية حدث {k} في <{tag}>")
                if k == "style":
                    bad.append(f"style داخل <{tag}>")
                if k in ("href", "src", "action") and v.strip().lower().startswith(("javascript:", "data:", "vbscript:")):
                    bad.append(f"رابط خطير في <{tag}>")
        return bad


def make_data(tmp: Path, systems: list[dict], status: dict | None = None) -> Path:
    d = tmp / "data"
    d.mkdir(parents=True, exist_ok=True)
    (d / "systems.json").write_text(json.dumps({"version": 1, "systems": systems}, ensure_ascii=False), encoding="utf-8")
    (d / "status.json").write_text(json.dumps(status or {}), encoding="utf-8")
    return d


def sys_entry(**kw) -> dict:
    base = {"id": "test-one", "name": "منظومة تجربة", "agency": "جهة تجربة", "url": "https://test.gov.ly/",
            "group": "citizen", "prepare": "الرقم الوطني، رقم الهاتف.", "steps": [],
            "registration_closed": False, "hidden": False, "popular": True}
    base.update(kw)
    return base


# ---------------------------------------------------------------- 1) الروابط
class TestURLs(unittest.TestCase):
    BAD = [
        "javascript:alert(1)",                    # تنفيذ كود
        "data:text/html,<script>alert(1)</script>",
        "http://cbl.gov.ly/",                     # بدون تشفير
        "//evil.com/",                            # بدون بروتوكول
        "https://gov.ly.evil.com/",               # نطاق مزيف يبدأ بالاسم الحكومي
        "https://evilgov.ly/",                    # نطاق يشبه gov.ly
        "https://cbl-gov.ly/",
        "https://cbl.gov.ly@evil.com/",           # خدعة اسم المستخدم
        "https://user:pass@cbl.gov.ly/",
        "https://evil.com\\@cbl.gov.ly/",         # خدعة الشرطة المائلة العكسية
        "https://1.2.3.4/",                       # عنوان IP
        "https://[::1]/",
        "https://cbl.gov.ly:8443/",               # منفذ غريب
        "https://сbl.gov.ly/",                    # حرف c روسي (هجوم الحروف المتشابهة)
        "https://cbl.gov.ly/\n<script>",          # أحرف تحكم
        'https://cbl.gov.ly/"onmouseover="x',     # كسر خاصية HTML
        "https://play.google.com/store/apps/evil",  # مسار غير مسموح
        "https://www.mhedusr.com.evil.com/",
        "",
        "https://" + "a" * 600 + ".gov.ly/",
    ]
    GOOD = [
        ("https://fcms.cbl.gov.ly/", "https://fcms.cbl.gov.ly/"),
        ("HTTPS://Ratebak.CBL.gov.ly", "https://ratebak.cbl.gov.ly"),
        ("https://mch.gate.mosa.ly/", "https://mch.gate.mosa.ly/"),
        ("https://play.google.com/store/apps/details?id=ly.zakat", "https://play.google.com/store/apps/details?id=ly.zakat"),
    ]

    def test_rejects_bad(self):
        for url in self.BAD:
            with self.subTest(url=url[:60]):
                with self.assertRaises(UnsafeURL):
                    check_url(url)

    def test_accepts_official(self):
        for url, expected in self.GOOD:
            with self.subTest(url=url):
                self.assertEqual(check_url(url), expected)

    def test_arabic_path_is_encoded(self):
        out = check_url("https://ejraat.gov.ly/خدمة")
        self.assertTrue(out.isascii())

    def test_all_real_links_pass(self):
        site = load_site(DATA)
        self.assertGreaterEqual(len(site.visible()), 30)


# ---------------------------------------------------------------- 2) البيانات
class TestData(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_path_traversal_id_rejected(self):
        for bad in ["../../etc/passwd", "a/b", "A-Upper", "x" * 80, "-start", "عربي", "a.html"]:
            with self.subTest(id=bad):
                d = make_data(self.tmp, [sys_entry(id=bad)])
                with self.assertRaises(DataError):
                    load_site(d)

    def test_bad_url_stops_build(self):
        d = make_data(self.tmp, [sys_entry(url="https://gov.ly.evil.com/")])
        with self.assertRaises(DataError):
            B.build(self.tmp / "out", d)
        self.assertFalse((self.tmp / "out" / "current").exists())

    def test_wrong_types_rejected(self):
        for kw in [{"hidden": "yes"}, {"name": ""}, {"name": 5}, {"group": "admin"},
                   {"steps": [{"title": "x"}]}, {"prepare": "x" * 700}]:
            with self.subTest(kw=str(kw)[:40]):
                d = make_data(self.tmp, [sys_entry(**kw)])
                with self.assertRaises(DataError):
                    load_site(d)

    def test_duplicate_id_rejected(self):
        d = make_data(self.tmp, [sys_entry(), sys_entry()])
        with self.assertRaises(DataError):
            load_site(d)

    def test_unknown_status_ignored(self):
        d = make_data(self.tmp, [sys_entry()], {"test-one": {"state": "<script>", "checked_at": 5}})
        s = load_site(d).systems[0]
        self.assertEqual(s.state, "unknown")
        self.assertIsNone(s.checked_at)


# ---------------------------------------------------------------- 3) حقن الكود في الصفحات (XSS)
class TestXSS(unittest.TestCase):
    PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
                "' onmouseover='alert(1)", '</title><script>alert(1)</script>', '<svg onload=alert(1)>']

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_payloads_are_escaped_everywhere(self):
        systems = []
        for i, p in enumerate(self.PAYLOADS):
            systems.append(sys_entry(id=f"x{i}", name=p, agency=p, prepare=p, conditions=p,
                                     steps=[{"title": p, "text": p}]))
        d = make_data(self.tmp, systems, {"x0": {"state": "down", "checked_at": "2026-10-07T00:00:00+00:00"}})
        out = B.build(self.tmp / "out", d)
        for f in out.rglob("*.html"):
            html = f.read_text(encoding="utf-8")
            with self.subTest(page=f.name):
                self.assertNotIn("<script>alert", html)
                self.assertNotIn("<img src=x", html)
                self.assertNotIn("<svg onload", html)
                self.assertEqual(TagScan(html).problems(), [])
                self.assertFalse(any(t == "img" for t, _ in TagScan(html).tags))


# ---------------------------------------------------------------- 4) فحص الصفحات الحقيقية
class TestBuiltSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.out = B.build(cls.tmp / "out", DATA)
        cls.pages = list(cls.out.rglob("*.html"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_csp_on_every_page(self):
        for f in self.pages:
            with self.subTest(page=f.name):
                self.assertIn('http-equiv="Content-Security-Policy"', f.read_text(encoding="utf-8"))

    def test_no_inline_script_style_or_handlers(self):
        for f in self.pages:
            html = f.read_text(encoding="utf-8")
            with self.subTest(page=f.name):
                self.assertEqual(TagScan(html).problems(), [])

    def test_every_external_link_is_official_and_safe(self):
        for f in self.pages:
            html = f.read_text(encoding="utf-8")
            for tag in re.findall(r"<a\b[^>]*>", html):
                href = re.search(r'href="([^"]*)"', tag).group(1)
                if href.startswith("http"):
                    with self.subTest(href=href):
                        if href.startswith("https://www.facebook.com/"):
                            self.assertEqual(href, B.facebook_url())   # رابط صفحتنا بس، ومتحقق منه
                        else:
                            check_url(href.replace("&amp;", "&"))
                        self.assertIn('rel="noopener noreferrer"', tag)

    def test_no_external_resources(self):
        for f in self.pages:
            html = f.read_text(encoding="utf-8")
            for m in re.findall(r'<(?:script|link|img)\b[^>]*(?:src|href)="([^"]+)"', html):
                with self.subTest(res=m):
                    self.assertFalse(m.startswith(("http", "//")), "مورد من موقع برّا")
        css = (self.out / "css" / "site.css").read_text(encoding="utf-8")
        self.assertNotRegex(css, r"url\(\s*['\"]?(https?:)?//")
        self.assertNotIn("@import", css)

    def test_js_has_no_dangerous_sinks(self):
        js = (self.out / "js" / "site.js").read_text(encoding="utf-8")
        for bad in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\""]:
            with self.subTest(sink=bad):
                self.assertNotIn(bad, js)

    def test_file_permissions(self):
        for f in self.out.rglob("*"):
            mode = stat.S_IMODE(f.stat().st_mode)
            with self.subTest(f=f.name):
                self.assertEqual(mode, 0o755 if f.is_dir() else 0o644)

    def test_no_secrets_or_internal_files_published(self):
        names = {p.name for p in self.out.rglob("*")}
        for bad in ["systems.json", "status.json", "config.py", ".env", ".git"]:
            self.assertNotIn(bad, names)
        for f in self.pages:
            self.assertNotIn("internal_note", f.read_text(encoding="utf-8"))

    def test_hidden_systems_not_published(self):
        raw = json.loads((DATA / "systems.json").read_text(encoding="utf-8"))
        for s in raw["systems"]:
            if s.get("hidden"):
                self.assertFalse((self.out / "s" / f"{s['id']}.html").exists())


# ---------------------------------------------------------------- 5) التبديل الذري
class TestAtomicDeploy(unittest.TestCase):
    def test_failed_build_keeps_old_site(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            out = tmp / "out"
            good = make_data(tmp / "g", [sys_entry()])
            first = B.build(out, good).resolve()
            bad = make_data(tmp / "b", [sys_entry(url="javascript:alert(1)")])
            with self.assertRaises(DataError):
                B.build(out, bad)
            self.assertEqual((out / "current").resolve(), first)
            self.assertFalse(any(p.name.startswith(".build-") for p in (out / "releases").iterdir()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_keeps_only_three_releases(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            d = make_data(tmp, [sys_entry()])
            for _ in range(5):
                B.build(tmp / "out", d)
            self.assertEqual(len([p for p in (tmp / "out" / "releases").iterdir()]), 3)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- 6) رابط الفيسبوك
class TestFacebook(unittest.TestCase):
    def tearDown(self):
        config.FACEBOOK_URL = ""

    def test_bad_facebook_rejected(self):
        for bad in ["javascript:alert(1)", "https://facebook.com.evil.com/x", "http://www.facebook.com/x",
                    'https://www.facebook.com/x"><script>']:
            with self.subTest(url=bad):
                config.FACEBOOK_URL = bad
                with self.assertRaises(DataError):
                    B.facebook_url()

    def test_good_facebook(self):
        config.FACEBOOK_URL = "https://www.facebook.com/manzumati.ly"
        self.assertIn('href="https://www.facebook.com/manzumati.ly" rel="noopener noreferrer"', B.fb_band(0))


# ---------------------------------------------------------------- 7) الفاحص
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path
        if p == "/ok":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        elif p == "/login":
            self.send_response(403); self.end_headers()
        elif p == "/fail":
            self.send_response(503); self.end_headers()
        elif p == "/evil":
            self.send_response(302); self.send_header("Location", "https://gov.ly.evil.com/phish"); self.end_headers()
        elif p == "/js":
            self.send_response(302); self.send_header("Location", "javascript:alert(1)"); self.end_headers()
        elif p == "/inside":
            self.send_response(302); self.send_header("Location", "/ok"); self.end_headers()
        elif p == "/loop":
            self.send_response(302); self.send_header("Location", "/loop"); self.end_headers()
        elif p == "/big":
            self.send_response(200); self.end_headers()
            try:
                for _ in range(2000):
                    self.wfile.write(b"x" * 65536)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(404); self.end_headers()


class TestChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.hosts = ("127.0.0.1",)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def p(self, path):
        return C.probe(self.base + path, self.hosts)

    def test_results(self):
        self.assertEqual(self.p("/ok"), "ok")
        self.assertEqual(self.p("/login"), "ok")          # السيرفر حي حتى لو طلب دخول
        self.assertEqual(self.p("/fail"), "fail")
        self.assertEqual(self.p("/inside"), "ok")
        self.assertEqual(self.p("/loop"), "fail")
        self.assertEqual(self.p("/no-such-page"), "fail")   # 404: الصفحة مش موجودة = واقفة
        self.assertEqual(C.probe("http://127.0.0.1:1/", self.hosts), "fail")

    def test_redirect_to_foreign_site_is_suspicious(self):
        self.assertEqual(self.p("/evil"), "suspicious")
        self.assertEqual(self.p("/js"), "suspicious")

    def test_big_response_is_capped(self):
        import time
        t = time.time()
        self.assertEqual(self.p("/big"), "ok")
        self.assertLess(time.time() - t, 10)

    def test_down_only_after_two_failures(self):
        s1 = C.next_state({"state": "up", "fails": 0}, "fail", "t")
        self.assertEqual(s1["state"], "up")
        s2 = C.next_state(s1, "fail", "t")
        self.assertEqual(s2["state"], "down")
        self.assertEqual(C.next_state(s2, "ok", "t")["state"], "up")

    def test_suspicious_hides_enter_button(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            d = make_data(tmp, [sys_entry(id="evil-redirect", url=self.base + "/evil")])
            status = C.run(d, extra_hosts=self.hosts, allow_http=True, workers=2)
            self.assertEqual(status["evil-redirect"]["state"], "suspicious")
            out = B.build(tmp / "out", d, extra_hosts=self.hosts, allow_http=True)
            html = (out / "s" / "evil-redirect.html").read_text(encoding="utf-8")
            self.assertNotIn(self.base, html)
            self.assertIn("الرابط تحت المراجعة", html)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
