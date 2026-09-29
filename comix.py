#!/usr/bin/env python3
"""
comix-downloader - search comix.to, list a title's chapters, download chapter images.

How it works
------------
comix.to's private API (/api/v1/...) protects itself in two ways:
  1. Each request carries a "_" query token computed by an obfuscated JS module
     (assets/.../secure-*.js) from the path + query params.
  2. Some responses come back encrypted as {"e": "..."} with header "x-enc: 1".

We don't re-implement that crypto (it changes with every site build). The script
downloads the site's own secure-*.js and runs it in a headless Chromium that
never touches the network (every request is intercepted locally). It's only used
to sign URLs and decrypt responses. The real HTTP traffic goes through curl_cffi,
which mimics Firefox's TLS fingerprint and sends your Cloudflare cookies.

If the site moves to another domain, use --domain NEW (or `domain NEW` to save it);
a redirect from the old domain is also detected automatically.

If Cloudflare still blocks plain HTTP, use --browser: a real (visible) browser
window opens the site, you solve the check once, and every API call is made
from inside that page.

Requirements:
    pip install curl_cffi playwright
    playwright install chromium          # (and firefox if you use --browser firefox)
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import quote, urlparse

__version__ = "1.0.0"

DEFAULT_DOMAIN = "comix.to"
ORIGIN = "https://" + DEFAULT_DOMAIN   # changed at runtime by --domain / config / env (see set_origin)
API = "/api/v1"
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
ALL_RATINGS = ["safe", "suggestive", "erotica", "pornographic"]
CONFIG_NAME = "comix_config.json"
USER_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "comix-downloader" / "config.json"
CACHE_DIR = Path(os.environ.get("COMIX_CACHE", Path.home() / ".cache" / "comix"))


class ComixError(Exception):
    pass


def normalize_origin(domain: str) -> str:
    """'comix.io' | 'https://comix.io/' | 'https://www.comix.io/title/x' -> 'https://comix.io' (keeps www/port)."""
    d = domain.strip()
    if not d:
        raise ComixError("empty domain")
    if "://" not in d:
        d = "https://" + d
    u = urlparse(d)
    if not u.hostname:
        raise ComixError(f"invalid domain: {domain!r}")
    return f"{u.scheme}://{u.netloc}".rstrip("/")


def set_origin(domain: str) -> str:
    global ORIGIN
    ORIGIN = normalize_origin(domain)
    return ORIGIN


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Query-string builder that matches axios' default serializer exactly
# (the "_" token is computed over the params, so the URL must match them).
# --------------------------------------------------------------------------- #
def _enc(v) -> str:
    if isinstance(v, bool):
        v = "true" if v else "false"
    # encodeURIComponent, then axios turns ! ' ( ) ~ back into %xx and %20 into +
    return quote(str(v), safe="-_.*").replace("%20", "+")


def build_query(params: dict) -> str:
    parts = []

    def walk(key, val):
        if val is None:
            return
        if isinstance(val, (list, tuple)):
            for item in val:
                parts.append(f"{_enc(key + '[]')}={_enc(item)}")
        elif isinstance(val, dict):
            for k, v in val.items():
                walk(f"{key}[{k}]", v)
        else:
            parts.append(f"{_enc(key)}={_enc(val)}")

    for k, v in params.items():
        walk(k, v)
    return "&".join(parts)


# --------------------------------------------------------------------------- #
# JavaScript glue: loads secure-*.js and exposes sign() / decrypt()
# --------------------------------------------------------------------------- #
SETUP_JS = r"""
async (securePath) => {
  const m = await import(securePath);
  const req = [], res = [];
  const fakeAxios = {
    defaults: { baseURL: '/api/v1', headers: {} },
    interceptors: {
      request:  { use: (f) => { req.push(f); return req.length - 1; } },
      response: { use: (f) => { res.push(f); return res.length - 1; } },
    },
  };
  m.r(fakeAxios);          // the site does exactly this with its axios instance
  if (!req.length || !res.length) throw new Error('secure module did not register interceptors');
  window.__cx = {
    async sign(url, params) {
      let c = { url, method: 'get', params: params || {}, headers: {}, baseURL: '/api/v1' };
      for (const f of req) c = await f(c);
      return { url: c.url, token: c.params ? c.params._ : undefined };
    },
    async decrypt(data) {
      let r = { data, status: 200, statusText: 'OK', headers: { 'x-enc': '1' }, config: {} };
      for (const f of res) r = await f(r);
      return r.data;
    },
  };
  return true;
}
"""

# used only in --browser mode: fetch from inside the real page
FETCH_JS = r"""
async ({url, headers}) => {
  const r = await fetch(url, { headers, credentials: 'include' });
  const text = await r.text();
  let data = null; try { data = JSON.parse(text); } catch (e) {}
  if (data && r.headers.get('x-enc') && data.e !== undefined) data = await window.__cx.decrypt(data);
  return { status: r.status, data, text: data === null ? text.slice(0, 500) : null };
}
"""


def _find_secure_path(html: str, fetch_text) -> tuple[str, str]:
    """Return (secure_js_path, cfg_meta) by following <script src=main-*.js> -> import './secure-*.js'."""
    cfg = ""
    mm = re.search(r'<meta name="cfg" content="([^"]*)"', html)
    if mm:
        cfg = mm.group(1)
    m = re.search(r'src="(/assets/[^"]+?/main-[^"]+?\.js)"', html)
    if not m:
        raise ComixError("Could not find main-*.js in the page HTML (Cloudflare page?)")
    main_path = m.group(1)
    main_js = fetch_text(main_path)
    s = re.search(r'from\s*"\./(secure-[^"]+?\.js)"', main_js)
    if not s:
        # maybe imported through env-*.js
        for dep in re.findall(r'from\s*"\./((?:env|vendor)-[^"]+?\.js)"', main_js):
            dep_js = fetch_text(main_path.rsplit("/", 1)[0] + "/" + dep)
            s = re.search(r'from\s*"\./(secure-[^"]+?\.js)"', dep_js)
            if s:
                break
    if not s:
        raise ComixError("Could not locate secure-*.js import. The site structure may have changed.")
    return main_path.rsplit("/", 1)[0] + "/" + s.group(1), cfg


class OfflineOracle:
    """Headless Chromium with *no network*: every request is answered locally.

    The secure module refuses to work on hosts it doesn't recognise, so the fake page is
    served on the site's own origin (falling back to the default domain if that fails).
    """

    def __init__(self, secure_path: str, secure_src: str, cfg: str, ua: str, origins: list[str] | None = None):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ComixError("playwright is missing:  pip install playwright && playwright install chromium")
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=True)
        except Exception as e:
            self._pw.stop()
            raise ComixError(f"Could not start Chromium ({e}). Run:  playwright install chromium")
        html = f'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="cfg" content="{cfg}"></head><body></body></html>'
        tried = []
        for origin in dict.fromkeys(origins or [ORIGIN, "https://" + DEFAULT_DOMAIN]):
            ctx = self._browser.new_context(user_agent=ua)

            def make_handler(page_url):
                def handler(route):
                    u = route.request.url.split("?")[0]
                    if u.endswith(secure_path):
                        route.fulfill(status=200, content_type="application/javascript", body=secure_src)
                    elif u == page_url:
                        route.fulfill(status=200, content_type="text/html", body=html)
                    else:
                        route.fulfill(status=204, body="")
                return handler

            ctx.route("**/*", make_handler(origin + "/__oracle"))
            try:
                self.page = ctx.new_page()
                self.page.goto(origin + "/__oracle")
                self.page.evaluate(SETUP_JS, secure_path)
                return
            except Exception as e:
                tried.append(f"{origin}: {str(e).splitlines()[0][:120]}")
                ctx.close()
        self.close()
        raise ComixError("The site's secure module could not be loaded:\n  " + "\n  ".join(tried))

    def sign(self, path: str, params: dict) -> str:
        return self.page.evaluate("([u,p]) => window.__cx.sign(u,p)", [path, params])["token"]

    def decrypt(self, data):
        return self.page.evaluate("(d) => window.__cx.decrypt(d)", data)

    def close(self):
        try:
            self._browser.close()
        finally:
            self._pw.stop()


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #
class HttpTransport:
    """curl_cffi (Firefox TLS fingerprint) + cookies, signing/decrypting via OfflineOracle."""

    def __init__(self, cookies: dict, ua: str, impersonate: str = "firefox", base: str | None = None):
        try:
            from curl_cffi import requests as creq
        except ImportError:
            raise ComixError("curl_cffi is missing:  pip install curl_cffi")
        self.base = (base or ORIGIN).rstrip("/")
        self.s = creq.Session(impersonate=impersonate, timeout=40)
        self.s.headers.update({
            "User-Agent": ua,
            "Accept-Language": "en-US,en;q=0.9",
        })
        host = urlparse(self.base).hostname
        for k, v in cookies.items():
            self.s.cookies.set(k, v, domain=host)
        self.ua = ua
        self.oracle = None

    def _get(self, url, **kw):
        last = None
        for attempt in range(4):
            try:
                r = self.s.get(url, **kw)
            except Exception as e:  # network hiccup
                last = e
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code in (429, 502, 503, 504) and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            return r
        raise ComixError(f"Request failed: {url} ({last})")

    @staticmethod
    def _is_cf_block(r) -> bool:
        return r.status_code in (403, 503) and (
            "cf-mitigated" in r.headers or "Just a moment" in r.text[:3000] or "challenge-platform" in r.text[:5000])

    def fetch_text(self, path: str) -> str:
        r = self._get(self.base + path, headers={"Referer": self.base + "/"})
        if self._is_cf_block(r):
            raise ComixError(
                "Cloudflare blocked the request. Refresh cf_clearance from the SAME browser/IP, keep the "
                "User-Agent identical to that browser, or run with --browser.")
        if r.status_code != 200:
            raise ComixError(f"GET {path} -> HTTP {r.status_code}")
        return r.text

    def _follow_domain_move(self):
        """If the site moved (old domain redirects to a new one), switch to the new origin automatically."""
        r = self._get(self.base + "/", headers={"Referer": self.base + "/"})
        final = normalize_origin(str(getattr(r, "url", "") or self.base))
        if urlparse(final).hostname != urlparse(self.base).hostname:
            log(f"[*] site redirected {self.base} -> {final}; using the new domain "
                f"(to remember it:  comix-downloader domain {urlparse(final).netloc})")
            old_host = urlparse(self.base).hostname
            self.base = final
            set_origin(final)
            new_host = urlparse(final).hostname
            for c in list(self.s.cookies.jar):
                if c.domain.lstrip(".") == old_host:
                    self.s.cookies.set(c.name, c.value, domain=new_host)

    def start(self):
        try:
            self._follow_domain_move()
        except ComixError:
            raise
        except Exception:
            pass
        html = self.fetch_text("/")
        secure_path, cfg = _find_secure_path(html, self.fetch_text)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached = CACHE_DIR / Path(secure_path).name
        if cached.exists():
            src = cached.read_text(encoding="utf-8")
        else:
            src = self.fetch_text(secure_path)
            cached.write_text(src, encoding="utf-8")
        self.oracle = OfflineOracle(secure_path, src, cfg, self.ua)
        return self

    def api_get(self, path: str, params: dict | None = None):
        params = dict(params or {})
        token = self.oracle.sign(path, params)
        if token is not None:
            params["_"] = token
        qs = build_query(params)
        url = f"{self.base}{API}{path}" + (f"?{qs}" if qs else "")
        r = self._get(url, headers={
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.base + "/",
        })
        if self._is_cf_block(r):
            raise ComixError("Cloudflare blocked the API call (update cf_clearance or use --browser).")
        try:
            data = r.json()
        except Exception:
            raise ComixError(f"API {path} -> HTTP {r.status_code}, non-JSON response: {r.text[:200]!r}")
        if r.status_code >= 400:
            raise ComixError(f"API {path} -> HTTP {r.status_code}: {str(data)[:300]}")
        if isinstance(data, dict) and set(data) == {"e"}:
            data = self.oracle.decrypt(data)
        return data

    def get_bytes(self, url: str, referer: str) -> tuple[bytes, str]:
        r = self._get(url, headers={"Referer": referer, "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        if r.status_code != 200:
            raise ComixError(f"HTTP {r.status_code}")
        return r.content, r.headers.get("content-type", "")

    def close(self):
        if self.oracle:
            self.oracle.close()


class BrowserTransport:
    """A real browser window on the site; API calls are made from inside the page."""

    def __init__(self, cookies: dict, ua: str | None, engine: str = "firefox", headless: bool = False,
                 base: str | None = None):
        self.base = (base or ORIGIN).rstrip("/")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ComixError("playwright is missing:  pip install playwright && playwright install " + engine)
        self._pw = sync_playwright().start()
        profile = CACHE_DIR / f"profile-{engine}"
        profile.mkdir(parents=True, exist_ok=True)
        kw = {"headless": headless}
        if ua:
            kw["user_agent"] = ua
        bt = getattr(self._pw, engine)
        try:
            self.ctx = bt.launch_persistent_context(str(profile), **kw)
        except Exception as e:
            self._pw.stop()
            raise ComixError(f"Could not start {engine} ({e}). Run:  playwright install {engine}")
        if cookies:
            self.ctx.add_cookies([{"name": k, "value": v, "url": self.base + "/"} for k, v in cookies.items()])
        self.page = self.ctx.pages[0] if self.ctx.pages else self.ctx.new_page()

    def start(self):
        self.page.goto(self.base + "/", wait_until="domcontentloaded")
        final = normalize_origin(self.page.url)
        if urlparse(final).hostname != urlparse(self.base).hostname and not final.startswith("about:"):
            log(f"[*] site redirected {self.base} -> {final}; using the new domain")
            self.base = final
            set_origin(final)
        deadline = time.time() + 180
        warned = False
        html = ""
        while True:
            try:
                html = self.page.evaluate(
                    "async () => { const r = await fetch('/', {credentials: 'include'}); return r.ok ? r.text() : ''; }")
            except Exception:
                html = ""  # page is navigating (e.g. Cloudflare redirect)
            if "/main-" in html and "<script" in html:
                break
            if time.time() > deadline:
                raise ComixError(f"{self.base} did not load within 3 minutes.")
            if not warned:
                log(f"[*] Waiting for {self.base}. If a Cloudflare check shows up in the browser window, solve it...")
                warned = True
            time.sleep(2)
        secure_path, _ = _find_secure_path(html, self._page_text)
        self.page.evaluate(SETUP_JS, secure_path)
        return self

    def _page_text(self, path):
        return self.page.evaluate("async (p) => (await fetch(p)).text()", path)

    def api_get(self, path, params=None):
        params = dict(params or {})
        token = self.page.evaluate("([u,p]) => window.__cx.sign(u,p)", [path, params])["token"]
        if token is not None:
            params["_"] = token
        qs = build_query(params)
        url = f"{API}{path}" + (f"?{qs}" if qs else "")
        for attempt in range(4):
            out = self.page.evaluate(FETCH_JS, {"url": url, "headers": {
                "Accept": "application/json, text/plain, */*", "X-Requested-With": "XMLHttpRequest"}})
            if out["status"] in (429, 502, 503, 504) and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            break
        if out["data"] is None:
            raise ComixError(f"API {path} -> HTTP {out['status']}: {out['text']!r}")
        if out["status"] >= 400:
            raise ComixError(f"API {path} -> HTTP {out['status']}: {str(out['data'])[:300]}")
        return out["data"]

    def get_bytes(self, url, referer):
        r = self.ctx.request.get(url, headers={"Referer": referer}, timeout=60000)
        if r.status != 200:
            raise ComixError(f"HTTP {r.status}")
        return r.body(), r.headers.get("content-type", "")

    def close(self):
        try:
            self.ctx.close()
        finally:
            self._pw.stop()


# --------------------------------------------------------------------------- #
# Site API
# --------------------------------------------------------------------------- #
def _unwrap(data):
    if isinstance(data, dict) and "result" in data and data.get("status") in ("ok", "success", None):
        return data["result"]
    return data


class Comix:
    SEARCH_PARAMS = ["keyword", "q", "search", "title"]

    def __init__(self, transport, ratings=None, search_param: str | None = None):
        self.t = transport
        self.ratings = ratings or ALL_RATINGS
        self._search_param = search_param

    # ---- search ----------------------------------------------------------- #
    def _search_once(self, pname, query, page, limit):
        params = {pname: query, "order": {"relevance": "desc"}, "content_rating": self.ratings,
                  "page": page, "limit": limit}
        return _unwrap(self.t.api_get("/manga", params))

    def search(self, query: str, page: int = 1, limit: int = 20):
        if self._search_param:
            return self._search_once(self._search_param, query, page, limit)
        words = [w for w in re.findall(r"\w+", query.lower()) if len(w) > 1]
        first = None
        for pname in self.SEARCH_PARAMS:
            try:
                res = self._search_once(pname, query, page, limit)
            except ComixError:
                continue
            first = first or res
            items = res.get("items", []) if isinstance(res, dict) else []
            blob = " ".join((i.get("title", "") + " " + " ".join(i.get("altTitles") or [])).lower() for i in items)
            if items and (not words or any(w in blob for w in words)):
                self._search_param = pname
                return res
        return first or {"items": [], "meta": {}}

    # ---- title ------------------------------------------------------------ #
    def manga(self, hid: str) -> dict:
        try:
            d = _unwrap(self.t.api_get(f"/manga/{hid}"))
            if isinstance(d, dict) and d.get("hid"):
                return d
        except ComixError:
            pass
        # fallback: the title page embeds the same data as JSON
        if hasattr(self.t, "fetch_text"):
            html = self.t.fetch_text(f"/title/{hid}")
        else:
            html = self.t._page_text(f"/title/{hid}")
        m = re.search(r'<script type="application/json" id="initial-data">(.*?)</script>', html, re.S)
        if m:
            for k, v in json.loads(m.group(1)).get("queries", {}).items():
                if '"detail"' in k and isinstance(v, dict) and v.get("hid"):
                    return v
        raise ComixError(f"Title '{hid}' not found")

    def chapters(self, hid: str, progress=True) -> list[dict]:
        out, page, limit = [], 1, 100
        while True:
            params = {"page": page, "limit": limit, "order": {"number": "desc"}}
            try:
                d = _unwrap(self.t.api_get(f"/manga/{hid}/chapters", params))
            except ComixError:
                if limit != 20 and page == 1:
                    limit = 20  # server may cap the page size
                    continue
                raise
            items = d.get("items", [])
            out.extend(items)
            meta = d.get("meta", {})
            if progress:
                log(f"    chapters page {page}/{meta.get('lastPage', '?')} ({len(out)}/{meta.get('total', '?')})")
            if not meta.get("hasNext") or not items:
                break
            page += 1
            time.sleep(0.3)
        return out

    def chapter(self, chapter_id: int) -> dict:
        return _unwrap(self.t.api_get(f"/chapters/{chapter_id}"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_target(s: str) -> tuple[str | None, int | None]:
    """'eqy5m' | '/title/eqy5m-slug' | full url (optionally with /<chapterId>-chapter-N) -> (hid, chapter_id)."""
    s = s.strip()
    m = re.search(r"/title/([a-z0-9]+)(?:-[^/]*)?(?:/(\d+)-chapter)?", s, re.I)
    if m:
        return m.group(1), (int(m.group(2)) if m.group(2) else None)
    if re.fullmatch(r"[a-z0-9]{3,8}", s, re.I) and re.search(r"\d", s):  # hids always contain a digit
        return s, None
    return None, None


def fmt_num(n) -> str:
    if n is None:
        return "?"
    f = float(n)
    if f.is_integer():
        return f"{int(f):03d}"
    whole, frac = str(f).split(".")
    return f"{int(whole):03d}.{frac}"


def safe_name(s: str, maxlen=120) -> str:
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", s).strip().rstrip(".")
    return s[:maxlen] or "untitled"


def parse_selection(sel: str, numbers: list[float]) -> set[float]:
    """'1-10,15,20.5,latest,all' -> set of chapter numbers."""
    if not sel or sel.strip().lower() == "all":
        return set(numbers)
    chosen = set()
    for part in sel.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part in ("latest", "last"):
            chosen.add(max(numbers))
        elif part.startswith("last") and part[4:].isdigit():  # last5
            chosen.update(sorted(set(numbers))[-int(part[4:]):])
        elif "-" in part:
            a, b = part.split("-", 1)
            lo = float(a) if a else min(numbers)
            hi = float(b) if b else max(numbers)
            chosen.update(n for n in numbers if lo <= n <= hi)
        else:
            chosen.add(float(part))
    return chosen


def pick_one_per_number(chs: list[dict], group: str | None) -> list[dict]:
    """Several scan groups can upload the same chapter; keep one per number."""
    by_num: dict[float, list[dict]] = {}
    for c in chs:
        by_num.setdefault(float(c["number"]), []).append(c)
    g = (group or "").lower()

    def score(c):
        gname = ((c.get("group") or {}).get("name") or "").lower()
        return (1 if g and g in gname else 0, 1 if c.get("isOfficial") else 0, c.get("votes") or 0, c.get("id") or 0)

    return [max(v, key=score) for _, v in sorted(by_num.items())]


def guess_ext(ctype: str, data: bytes, url: str) -> str:
    sig = data[:12]
    if sig.startswith(b"\xff\xd8"):
        return ".jpg"
    if sig.startswith(b"\x89PNG"):
        return ".png"
    if sig[:4] == b"RIFF" and sig[8:12] == b"WEBP":
        return ".webp"
    if sig[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if sig[4:12] in (b"ftypavif", b"ftypavis"):
        return ".avif"
    for k, e in (("jpeg", ".jpg"), ("png", ".png"), ("webp", ".webp"), ("gif", ".gif"), ("avif", ".avif")):
        if k in ctype:
            return e
    m = re.search(r"\.(jpe?g|png|webp|gif|avif)(?:$|\?)", url, re.I)
    return "." + m.group(1).lower() if m else ".img"


def chapter_label(c: dict) -> str:
    s = f"Ch.{fmt_num(c.get('number'))}"
    if c.get("volume"):
        s = f"Vol.{c['volume']} " + s
    if c.get("name"):
        s += f" - {c['name']}"
    return s


def print_manga(m: dict):
    genres = ", ".join(g["title"] for g in m.get("genres", []) or [])
    print(f"\n{m.get('title')}  [{m.get('hid')}]  {ORIGIN}{m.get('url', '')}")
    print(f"  type: {m.get('type')}  status: {m.get('status')}  year: {m.get('year')}  "
          f"rating: {m.get('contentRating')}  score: {m.get('ratedAvg')}  latest: {m.get('latestChapter')}")
    if genres:
        print(f"  genres: {genres}")
    if m.get("authors"):
        print(f"  authors: {', '.join(a['title'] for a in m['authors'])}")


def print_chapters(chs: list[dict]):
    print(f"\n  {'#':>4}  {'chapter':<22} {'group':<22} {'votes':>5}  {'added':<12} id")
    for i, c in enumerate(chs, 1):
        gname = (c.get("group") or {}).get("name") or ("user:" + ((c.get("creator") or {}).get("name") or "?"))
        print(f"  {i:>4}  {chapter_label(c)[:22]:<22} {gname[:22]:<22} {c.get('votes') or 0:>5}  {c.get('createdAtFormatted', ''):<12} {c.get('id')}")


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #
def download_chapter(api: Comix, manga_title: str, ch: dict, out_dir: Path, workers: int, cbz: bool,
                     keep_folder: bool) -> Path:
    detail = api.chapter(ch["id"])
    pages = (detail.get("pages") or {})
    base = pages.get("baseUrl") or ""
    items = pages.get("items") or []
    if not items:
        raise ComixError(f"{chapter_label(ch)}: no pages returned")
    gname = (detail.get("group") or ch.get("group") or {}).get("name") or ""
    folder = out_dir / safe_name(manga_title) / safe_name(chapter_label(detail) + (f" [{gname}]" if gname else ""))
    cbz_path = folder.parent / (folder.name + ".cbz")
    if cbz and cbz_path.exists():
        log(f"  = {cbz_path.name} already exists, skipping")
        return cbz_path
    folder.mkdir(parents=True, exist_ok=True)
    referer = ORIGIN + (detail.get("url") or "/")

    def one(idx_item):
        idx, it = idx_item
        url = it["url"] if it["url"].startswith("http") else base + it["url"]
        existing = list(folder.glob(f"{idx:03d}.*"))
        if existing and existing[0].stat().st_size > 0:
            return "skip"
        err = None
        for attempt in range(4):
            try:
                data, ctype = api.t.get_bytes(url, referer)
                if not data:
                    raise ComixError("empty response")
                (folder / f"{idx:03d}{guess_ext(ctype, data, url)}").write_bytes(data)
                return "ok"
            except Exception as e:
                err = e
                time.sleep(1.5 * (attempt + 1))
        return f"fail: {err}"

    jobs = list(enumerate(items, 1))
    if isinstance(api.t, BrowserTransport):
        results = [one(j) for j in jobs]  # playwright objects are single-threaded
    else:
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(one, jobs))
    fails = [r for r in results if r.startswith("fail")]
    (folder / "chapter.json").write_text(json.dumps(detail, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"  + {folder.name}: {len(items) - len(fails)}/{len(items)} pages" + (f"  ({len(fails)} failed)" if fails else ""))
    if cbz and not fails:
        with zipfile.ZipFile(cbz_path, "w", zipfile.ZIP_STORED) as z:
            for f in sorted(folder.iterdir()):
                if f.name != "chapter.json":
                    z.write(f, f.name)
        if not keep_folder:
            for f in folder.iterdir():
                f.unlink()
            folder.rmdir()
        return cbz_path
    return folder


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def config_candidates(path: str | None) -> list[Path]:
    if path:
        return [Path(path)]
    return [Path.cwd() / CONFIG_NAME, Path(__file__).resolve().with_name(CONFIG_NAME), USER_CONFIG]


def find_config(path: str | None) -> Path | None:
    for p in config_candidates(path):
        if p.exists():
            return p
    return None


def load_config(path: str | None) -> dict:
    p = find_config(path)
    if not p:
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ComixError(f"{p}: invalid JSON ({e})")


def save_config_value(path: str | None, key: str, value) -> Path:
    p = find_config(path) or (Path(path) if path else USER_CONFIG)
    cfg = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    cfg[key] = value
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def resolve_domain(args, cfg: dict) -> str:
    """Priority: --domain > COMIX_DOMAIN env > config "domain" > default."""
    return args.domain or os.environ.get("COMIX_DOMAIN") or cfg.get("domain") or DEFAULT_DOMAIN


def parse_cookie_str(s: str) -> dict:
    out = {}
    for part in s.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def make_api(args) -> Comix:
    cfg = load_config(args.config)
    cookies = dict(cfg.get("cookies") or {})
    if os.environ.get("COMIX_COOKIES"):
        cookies.update(parse_cookie_str(os.environ["COMIX_COOKIES"]))
    if args.cookie:
        cookies.update(parse_cookie_str(args.cookie))
    ua = args.user_agent or cfg.get("user_agent") or DEFAULT_UA
    ratings = args.ratings.split(",") if args.ratings else cfg.get("content_rating") or ALL_RATINGS
    set_origin(resolve_domain(args, cfg))
    log(f"[*] site: {ORIGIN}")
    if args.browser:
        log(f"[*] starting {args.browser} (browser mode)...")
        t = BrowserTransport(cookies, ua if args.browser == "firefox" else None, engine=args.browser,
                             headless=args.headless)
    else:
        log("[*] connecting (curl_cffi + offline JS signer)...")
        t = HttpTransport(cookies, ua, impersonate=cfg.get("impersonate", "firefox"),
                          base=os.environ.get("COMIX_HTTP_BASE"))  # HTTP_BASE: testing only
    t.start()
    if args.save_domain:
        p = save_config_value(args.config, "domain", urlparse(ORIGIN).netloc)
        log(f"[*] saved domain {urlparse(ORIGIN).netloc} -> {p}")
    return Comix(t, ratings=ratings, search_param=args.search_param or cfg.get("search_param"))


def resolve_hid(api: Comix, target: str) -> tuple[str, int | None]:
    hid, chap = parse_target(target)
    if hid:
        return hid, chap
    res = api.search(target, limit=5)
    items = res.get("items", [])
    if not items:
        raise ComixError(f"No results for '{target}'")
    log(f"[*] '{target}' -> {items[0]['title']} [{items[0]['hid']}]")
    return items[0]["hid"], None


def cmd_search(api: Comix, args):
    res = api.search(args.query, page=args.page, limit=args.limit)
    items = res.get("items", [])
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return
    meta = res.get("meta", {})
    print(f"\n{meta.get('total', len(items))} result(s) - page {meta.get('page', 1)}/{meta.get('lastPage', 1)}")
    for i, m in enumerate(items, 1):
        print(f"  {i:>2}. [{m['hid']}] {m['title']}  ({m.get('type')}, {m.get('status')}, "
              f"latest {m.get('latestChapter')}, {m.get('contentRating')}, ★{m.get('ratedAvg')})")
    return items


def cmd_info(api: Comix, args):
    hid, _ = resolve_hid(api, args.target)
    m = api.manga(hid)
    chs = api.chapters(hid)
    if args.group:
        chs = [c for c in chs if args.group.lower() in ((c.get("group") or {}).get("name") or "").lower()]
    if args.json:
        Path(args.json).write_text(json.dumps({"manga": m, "chapters": chs}, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
        log(f"[*] saved -> {args.json}")
    print_manga(m)
    groups = sorted({(c.get("group") or {}).get("name") or "(user upload)" for c in chs})
    print(f"  chapters: {len(chs)} entries, {len({float(c['number']) for c in chs})} unique numbers")
    print(f"  groups: {', '.join(groups)}")
    print_chapters(chs)


def cmd_download(api: Comix, args, preloaded=None):
    if preloaded:
        (hid, m, chs_cached), chap_id = preloaded, None
    else:
        hid, chap_id = resolve_hid(api, args.target)
        m, chs_cached = api.manga(hid), None
    out = Path(args.out)
    if chap_id and not args.chapters:
        ch = api.chapter(chap_id)
        log(f"[*] {m['title']} - {chapter_label(ch)}")
        download_chapter(api, m["title"], ch, out, args.workers, args.cbz, args.keep_folder)
        return
    chs = chs_cached if chs_cached is not None else api.chapters(hid)
    if args.group:
        g = [c for c in chs if args.group.lower() in ((c.get("group") or {}).get("name") or "").lower()]
        if not g:
            if args.strict_group:
                raise ComixError(f"No chapters from group '{args.group}'")
            log(f"[!] no chapters from group '{args.group}', using any group")
        elif args.strict_group:
            chs = g
    wanted = parse_selection(args.chapters or "all", [float(c["number"]) for c in chs])
    chs = [c for c in chs if float(c["number"]) in wanted]
    if not args.all_groups:
        chs = pick_one_per_number(chs, args.group)
    else:
        chs = sorted(chs, key=lambda c: float(c["number"]))
    if not chs:
        raise ComixError("No chapter matches the selection")
    log(f"[*] {m['title']}: downloading {len(chs)} chapter(s) -> {out.resolve()}")
    for i, c in enumerate(chs, 1):
        log(f"[{i}/{len(chs)}] {chapter_label(c)} ({(c.get('group') or {}).get('name', '')})")
        try:
            download_chapter(api, m["title"], c, out, args.workers, args.cbz, args.keep_folder)
        except ComixError as e:
            log(f"  ! {e}")
        time.sleep(args.delay)


def cmd_domain(args):
    cfg = load_config(args.config)
    if not args.new_domain:
        src = "--domain" if args.domain else "COMIX_DOMAIN" if os.environ.get("COMIX_DOMAIN") else \
            ("config" if cfg.get("domain") else "default")
        print(f"current domain: {normalize_origin(resolve_domain(args, cfg))}  (from {src})")
        print(f"config file:    {find_config(args.config) or '(none)'}")
        return
    origin = normalize_origin(args.new_domain)
    p = save_config_value(args.config, "domain", urlparse(origin).netloc)
    print(f"domain set to {origin}  (saved in {p})")


def cmd_interactive(api: Comix, args):
    q = input(f"Search title (or paste a {urlparse(ORIGIN).netloc} URL): ").strip()
    hid, chap = parse_target(q)
    if not hid:
        items = cmd_search(api, argparse.Namespace(query=q, page=1, limit=20, json=False))
        if not items:
            return
        sel = input("Pick a number: ").strip()
        hid = items[int(sel) - 1]["hid"]
    m = api.manga(hid)
    chs = api.chapters(hid)
    print_manga(m)
    groups = sorted({(c.get("group") or {}).get("name") or "(user upload)" for c in chs})
    print(f"  groups: {', '.join(groups)}")
    print_chapters(chs)
    sel = input("\nChapters to download (e.g. 1-10,15 | latest | last5 | all | empty = cancel): ").strip()
    if not sel:
        return
    grp = input("Preferred group (empty = auto): ").strip() or None
    cbz = input("Pack as .cbz? [y/N]: ").strip().lower() == "y"
    ns = argparse.Namespace(target=hid, chapters=sel, group=grp, strict_group=False, all_groups=False,
                            out=args.out, workers=args.workers, cbz=cbz, keep_folder=False, delay=args.delay)
    cmd_download(api, ns, preloaded=(hid, m, chs))


def main():
    p = argparse.ArgumentParser(prog="comix-downloader",
                                description="Search comix.to, list chapters and download them.")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-d", "--domain", help=f"site domain if it moved, e.g. comix.io (default {DEFAULT_DOMAIN})")
    p.add_argument("--save-domain", action="store_true", help="remember --domain (or an auto-detected move) in the config")
    p.add_argument("--config", help=f"config JSON (default: ./{CONFIG_NAME} or {USER_CONFIG})")
    p.add_argument("--cookie", help='cookies, e.g. "cf_clearance=...; session=..."')
    p.add_argument("--user-agent", help="must match the browser that produced cf_clearance")
    p.add_argument("--ratings", help="content ratings, default: safe,suggestive,erotica,pornographic")
    p.add_argument("--search-param", help="force the API search parameter name (auto-detected by default)")
    p.add_argument("--browser", choices=["firefox", "chromium"], help="use a real browser window instead of plain HTTP")
    p.add_argument("--headless", action="store_true", help="with --browser: hide the window")
    p.add_argument("--out", default="downloads", help="output folder (default: downloads)")
    p.add_argument("--workers", type=int, default=6, help="parallel image downloads (default 6)")
    p.add_argument("--delay", type=float, default=0.5, help="pause between chapters, seconds")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("search", help="search titles")
    s.add_argument("query")
    s.add_argument("--page", type=int, default=1)
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true", help="print raw JSON")

    i = sub.add_parser("info", help="title details + full chapter list")
    i.add_argument("target", help="hid, title URL, or a search phrase")
    i.add_argument("--group", help="only chapters from this scan group")
    i.add_argument("--json", metavar="FILE", help="save title + chapters to a JSON file")

    d = sub.add_parser("download", help="download chapter images")
    d.add_argument("target", help="hid, title URL, chapter URL, or a search phrase")
    d.add_argument("-c", "--chapters", help="e.g. 1-10,15,20.5 | latest | last5 | all (default all)")
    d.add_argument("-g", "--group", help="preferred scan group (substring)")
    d.add_argument("--strict-group", action="store_true", help="only that group, never fall back")
    d.add_argument("--all-groups", action="store_true", help="download every group's version")
    d.add_argument("--cbz", action="store_true", help="pack each chapter into a .cbz")
    d.add_argument("--keep-folder", action="store_true", help="keep image folder after making .cbz")

    dm = sub.add_parser("domain", help="show or change the saved site domain")
    dm.add_argument("new_domain", nargs="?", help="e.g. comix.io  (omit to show the current one)")

    args = p.parse_args()
    if args.cmd == "domain":
        try:
            cmd_domain(args)
        except ComixError as e:
            log(f"[error] {e}")
            sys.exit(1)
        return
    api = None
    try:
        api = make_api(args)
        if args.cmd == "search":
            cmd_search(api, args)
        elif args.cmd == "info":
            cmd_info(api, args)
        elif args.cmd == "download":
            cmd_download(api, args)
        else:
            cmd_interactive(api, args)
    except ComixError as e:
        log(f"[error] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        log("\n[interrupted]")
        sys.exit(130)
    finally:
        if api:
            api.t.close()


if __name__ == "__main__":
    main()
