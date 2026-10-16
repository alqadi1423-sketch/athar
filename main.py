"""أثر: محرك بحث عن اسم مستخدم عبر مئات المنصات العامة.

يفحص كل منصة بالتوازي ويبث النتائج للمتصفح لحظة وصولها (Server-Sent Events).
"""
import asyncio
import json
import re
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse

BASE = Path(__file__).parent
SITES: dict = json.loads((BASE / "sites.json").read_text(encoding="utf-8"))
SITES.pop("_license", None)  # نص ترخيص قائمة المنصات (MIT)، يجب إبقاؤه في الملف

# أسماء محجوبة من البحث بطلب أصحابها، اكتبها بحروف صغيرة
BLOCKLIST: set[str] = set()

CONCURRENCY = 50          # عدد الطلبات المتزامنة لكل بحث
TIMEOUT = 12.0            # ثوانٍ لكل منصة
RATE_LIMIT = 10           # عدد عمليات البحث المسموحة لكل IP
RATE_WINDOW = 60 * 10     # خلال 10 دقائق
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

app = FastAPI(title="Athar")
_hits: dict[str, deque] = defaultdict(deque)


def rate_ok(ip: str) -> bool:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return False
    q.append(now)
    return True


def fill(obj, username: str):
    """يستبدل {} باسم المستخدم داخل نص أو قاموس أو قائمة."""
    if isinstance(obj, str):
        return obj.replace("{}", username)
    if isinstance(obj, dict):
        return {k: fill(v, username) for k, v in obj.items()}
    if isinstance(obj, list):
        return [fill(v, username) for v in obj]
    return obj


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


async def check_site(client: httpx.AsyncClient, name: str, site: dict, username: str) -> dict:
    url = site["url"].replace("{}", username)
    result = {"site": name, "url": url, "home": site.get("urlMain", ""), "status": "none"}

    regex = site.get("regexCheck")
    if regex and not re.search(regex, username):
        result["status"] = "invalid"
        return result

    probe = site.get("urlProbe", site["url"]).replace("{}", username)
    etype = site["errorType"]
    method = site.get("request_method") or "GET"
    payload = fill(site.get("request_payload"), username)
    headers = {**HEADERS, **site.get("headers", {})}
    follow = etype != "response_url"

    try:
        r = await client.request(
            method, probe, headers=headers, json=payload,
            follow_redirects=follow, timeout=TIMEOUT,
        )
    except Exception:
        result["status"] = "error"
        return result

    found = False
    if etype == "message":
        text = r.text
        found = not any(msg in text for msg in as_list(site.get("errorMsg")))
        if r.status_code >= 400:
            found = False
    elif etype == "status_code":
        codes = as_list(site.get("errorCode"))
        found = not (r.status_code in codes or r.status_code >= 300 or r.status_code < 200)
    elif etype == "response_url":
        found = 200 <= r.status_code < 300

    result["status"] = "found" if found else "none"
    return result


@app.get("/")
async def index():
    return FileResponse(BASE / "index.html")


@app.get("/api/stats")
async def stats():
    return {"platforms": len(SITES)}


@app.get("/api/search")
async def search(u: str, request: Request):
    username = u.strip().lstrip("@")
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم غير صالح")
    ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    if not rate_ok(ip):
        raise HTTPException(429, "تجاوزت الحد المسموح، حاول بعد قليل")

    async def stream():
        total = len(SITES)
        yield f"event: start\ndata: {json.dumps({'total': total})}\n\n"
        if username.lower() in BLOCKLIST:
            yield f"event: done\ndata: {json.dumps({'found': 0, 'blocked': True})}\n\n"
            return

        started = time.time()
        sem = asyncio.Semaphore(CONCURRENCY)
        limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=20)
        async with httpx.AsyncClient(limits=limits, http2=False, verify=True) as client:

            async def run(name, site):
                async with sem:
                    return await check_site(client, name, site, username)

            tasks = [asyncio.create_task(run(n, s)) for n, s in SITES.items()]
            found = 0
            try:
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    if res["status"] == "found":
                        found += 1
                    yield f"event: result\ndata: {json.dumps(res, ensure_ascii=False)}\n\n"
                    if await request.is_disconnected():
                        break
            finally:
                for t in tasks:
                    t.cancel()

        took = round(time.time() - started, 1)
        yield f"event: done\ndata: {json.dumps({'found': found, 'seconds': took})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
