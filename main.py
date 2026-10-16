"""أثر: محرك بحث عن اسم مستخدم عبر المنصات العامة، مع بطاقة كاملة لكل حساب.

1. معايرة ذاتية: يجرب الخادم كل منصة على حساب معروف وحساب وهمي، ويستبعد المنصات التي تعطي نتائج خاطئة.
2. بحث متوازٍ يبث النتائج للمتصفح لحظة تأكيدها.
3. استخراج بيانات الحساب العامة (الصورة، الاسم، النبذة، الأرقام، تاريخ الإنشاء...) لكل حساب موجود.
"""
import asyncio
import html as htmllib
import json
import random
import re
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse

BASE = Path(__file__).parent
SITES: dict = json.loads((BASE / "sites.json").read_text(encoding="utf-8"))
SITES.pop("_license", None)  # نص ترخيص قائمة المنصات (MIT)، يجب إبقاؤه في الملف

# أسماء محجوبة من البحث بطلب أصحابها، اكتبها بحروف صغيرة
BLOCKLIST: set[str] = set()

CONCURRENCY = 60
TIMEOUT = 15.0
RATE_LIMIT = 15
RATE_WINDOW = 600
CALIBRATE_EVERY = 6 * 3600
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# تعديلات وإضافات على قائمة المنصات
SITES.update({
    "Instagram": {
        "errorType": "status_code",
        "url": "https://www.instagram.com/{}/",
        "urlMain": "https://www.instagram.com/",
        "urlProbe": "https://i.instagram.com/api/v1/users/web_profile_info/?username={}",
        "headers": {"x-ig-app-id": "936619743392459", "Accept": "*/*"},
        "regexCheck": r"^[A-Za-z0-9._]{1,30}$",
        "username_claimed": "instagram",
    },
    "threads": {
        "errorType": "message",
        "errorMsg": ["<title>Threads</title>", "<title>Threads • Log in</title>"],
        "url": "https://www.threads.net/@{}",
        "urlMain": "https://www.threads.net/",
        "regexCheck": r"^[A-Za-z0-9._]{1,30}$",
        "username_claimed": "zuck",
    },
})

app = FastAPI(title="Athar")
_hits: dict[str, deque] = defaultdict(deque)

# ───────────── أدوات عامة ─────────────

def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def fill(obj, username):
    if isinstance(obj, str):
        return obj.replace("{}", username)
    if isinstance(obj, dict):
        return {k: fill(v, username) for k, v in obj.items()}
    if isinstance(obj, list):
        return [fill(v, username) for v in obj]
    return obj


def client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()


def rate_ok(ip: str) -> bool:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return False
    q.append(now)
    return True


def to_int(v):
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    s = str(v).strip().replace(",", "").replace(" ", "").replace(" ", "")
    m = re.match(r"^([\d.]+)([KkMmBb]?)$", s)
    if not m:
        return None
    n = float(m.group(1))
    n *= {"k": 1e3, "m": 1e6, "b": 1e9}.get(m.group(2).lower(), 1)
    return int(n)


def iso(ts):
    """يحوّل طابعًا زمنيًا (ثوانٍ أو ملّي ثانية أو نص) إلى تاريخ ISO."""
    if ts in (None, "", 0):
        return None
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.isdigit()):
            t = float(ts)
            if t > 1e12:
                t /= 1000
            return datetime.fromtimestamp(t, tz=timezone.utc).date().isoformat()
        return str(ts)[:10]
    except Exception:
        return None


META_RE = re.compile(r"<meta\s+[^>]*?>", re.I | re.S)
ATTR_RE = re.compile(r'([\w:-]+)\s*=\s*("([^"]*)"|\'([^\']*)\')', re.S)


def parse_meta(text: str) -> dict:
    out = {}
    for tag in META_RE.findall(text[:400_000]):
        attrs = {m.group(1).lower(): (m.group(3) if m.group(3) is not None else m.group(4)) for m in ATTR_RE.finditer(tag)}
        key = attrs.get("property") or attrs.get("name") or attrs.get("itemprop")
        val = attrs.get("content")
        if key and val and key.lower() not in out:
            out[key.lower()] = htmllib.unescape(val).strip()
    t = re.search(r"<title[^>]*>(.*?)</title>", text[:200_000], re.I | re.S)
    if t:
        out["_title"] = htmllib.unescape(t.group(1)).strip()
    return out


def json_script(text: str, script_id: str):
    m = re.search(rf'<script[^>]+id="{re.escape(script_id)}"[^>]*>(.*?)</script>', text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def dig(d, *path):
    for p in path:
        if isinstance(d, dict):
            d = d.get(p)
        elif isinstance(d, list) and isinstance(p, int) and len(d) > p:
            d = d[p]
        else:
            return None
    return d


URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)
HANDLE_RE = re.compile(r"(?<![\w.])@([A-Za-z0-9_.]{3,30})")


def discover(*texts) -> list[str]:
    """يلتقط الروابط والمعرّفات المذكورة في النبذة والروابط."""
    found = []
    for t in texts:
        if not t:
            continue
        for u in URL_RE.findall(str(t)):
            found.append(u.rstrip(".,"))
        for h in HANDLE_RE.findall(str(t)):
            found.append("@" + h.rstrip("."))
    seen, out = set(), []
    for x in found:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out[:15]


def profile(**kw) -> dict:
    """يبني بطاقة حساب موحدة ويحذف الحقول الفارغة."""
    fields = {k: v for k, v in (kw.pop("fields", None) or {}).items() if v not in (None, "", [], {})}
    p = {k: v for k, v in kw.items() if v not in (None, "", [], {})}
    if fields:
        p["fields"] = fields
    return p


# ───────────── مستخرجات مخصصة لكل منصة ─────────────
# كل دالة تأخذ (client, username, text) حيث text هو محتوى صفحة الفحص إن وُجد

async def get_json(client, url, **kw):
    r = await client.get(url, headers={**HEADERS, "Accept": "application/json", **kw.pop("headers", {})},
                         timeout=TIMEOUT, follow_redirects=True, **kw)
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None


async def x_github(c, u, text):
    d = await get_json(c, f"https://api.github.com/users/{u}")
    if not d or "login" not in d:
        return None
    return profile(
        name=d.get("name"), handle=d.get("login"), avatar=d.get("avatar_url"), bio=d.get("bio"),
        followers=d.get("followers"), following=d.get("following"), posts=d.get("public_repos"),
        posts_label="مستودع", location=d.get("location"), joined=iso(d.get("created_at")),
        website=d.get("blog"), uid=d.get("id"),
        fields={"الشركة": d.get("company"), "تويتر": d.get("twitter_username"),
                "آخر تحديث": iso(d.get("updated_at")), "النوع": d.get("type")},
        links=discover(d.get("bio"), d.get("blog"),
                       f"@{d['twitter_username']}" if d.get("twitter_username") else None),
    )


async def x_gitlab(c, u, text):
    d = await get_json(c, f"https://gitlab.com/api/v4/users?username={u}")
    if not d:
        return None
    d0 = d[0]
    full = await get_json(c, f"https://gitlab.com/api/v4/users/{d0['id']}") or d0
    return profile(
        name=full.get("name"), handle=full.get("username"), avatar=full.get("avatar_url"),
        bio=full.get("bio"), location=full.get("location"), joined=iso(full.get("created_at")),
        website=full.get("website_url"), uid=full.get("id"),
        followers=full.get("followers"), following=full.get("following"),
        fields={"الوظيفة": full.get("job_title"), "المؤسسة": full.get("organization"),
                "تويتر": full.get("twitter"), "لينكدإن": full.get("linkedin")},
        links=discover(full.get("bio"), full.get("website_url")),
    )


async def x_tiktok(c, u, text):
    if not text:
        r = await c.get(f"https://www.tiktok.com/@{u}", headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        text = r.text
    data = json_script(text, "__UNIVERSAL_DATA_FOR_REHYDRATION__")
    info = dig(data, "__DEFAULT_SCOPE__", "webapp.user-detail", "userInfo")
    user = (info or {}).get("user") or {}
    stats = (info or {}).get("statsV2") or (info or {}).get("stats") or {}
    if not user.get("uniqueId"):
        return None
    uid = user.get("id")
    created = user.get("createTime")
    if not created and uid and str(uid).isdigit():
        created = int(uid) >> 32  # معرّف تيك توك يحمل وقت الإنشاء في أعلى 32 بت
    bio_link = dig(user, "bioLink", "link")
    return profile(
        name=user.get("nickname"), handle=user.get("uniqueId"),
        avatar=user.get("avatarLarger") or user.get("avatarMedium"), bio=user.get("signature"),
        verified=user.get("verified"), private=user.get("privateAccount"),
        followers=to_int(stats.get("followerCount")), following=to_int(stats.get("followingCount")),
        posts=to_int(stats.get("videoCount")), posts_label="فيديو",
        likes=to_int(stats.get("heartCount") or stats.get("heart")),
        joined=iso(created), uid=uid, website=bio_link,
        fields={
            "الدولة": user.get("region"), "لغة الحساب": user.get("language"),
            "الأصدقاء": to_int(stats.get("friendCount")),
            "آخر تغيير للاسم": iso(user.get("nickNameModifyTime")),
            "آخر تغيير للمعرّف": iso(user.get("uniqueIdModifyTime")),
            "حساب تجاري": "نعم" if dig(user, "commerceUserInfo", "commerceUser") else None,
            "بائع": "نعم" if user.get("ttSeller") else None,
            "حساب منظمة": "نعم" if user.get("isOrganization") else None,
            "قائمة المتابَعين": {0: "علنية", 1: "للأصدقاء", 2: "خاصة"}.get(user.get("followingVisibility")),
            "secUid": user.get("secUid"),
        },
        links=discover(user.get("signature"), bio_link),
    )


async def x_snapchat(c, u, text):
    if not text:
        r = await c.get(f"https://www.snapchat.com/add/{u}", headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        text = r.text
    data = json_script(text, "__NEXT_DATA__")
    up = dig(data, "props", "pageProps", "userProfile") or {}
    info = up.get("publicProfileInfo") or up.get("userInfo") or {}
    if not info:
        return None
    bitmoji = dig(info, "bitmoji3d", "avatarImage", "url") or dig(info, "bitmoji2d", "avatarImage", "url")
    return profile(
        name=info.get("title") or info.get("displayName"), handle=info.get("username") or u,
        avatar=dig(info, "profilePictureUrl") or bitmoji, banner=info.get("squareHeroImageUrl"),
        bio=info.get("bio"), followers=to_int(info.get("subscriberCount")),
        location=info.get("address"), website=info.get("websiteUrl"),
        verified=bool(info.get("badge")) or None,
        fields={"التصنيف": info.get("categoryStringId"), "حساب عام": "نعم" if up.get("publicProfileInfo") else None},
        links=discover(info.get("bio"), info.get("websiteUrl")),
    )


async def x_instagram(c, u, text):
    d = None
    if text:
        try:
            d = json.loads(text)
        except Exception:
            d = None
    if not d:
        d = await get_json(c, f"https://i.instagram.com/api/v1/users/web_profile_info/?username={u}",
                           headers={"x-ig-app-id": "936619743392459"})
    user = dig(d, "data", "user")
    if not user:
        return None
    return profile(
        name=user.get("full_name"), handle=user.get("username"),
        avatar=user.get("profile_pic_url_hd") or user.get("profile_pic_url"), bio=user.get("biography"),
        verified=user.get("is_verified"), private=user.get("is_private"),
        followers=dig(user, "edge_followed_by", "count"), following=dig(user, "edge_follow", "count"),
        posts=dig(user, "edge_owner_to_timeline_media", "count"), website=user.get("external_url"),
        uid=user.get("id"),
        fields={"حساب تجاري": "نعم" if user.get("is_business_account") else None,
                "التصنيف": user.get("category_name") or user.get("business_category_name"),
                "حساب جديد": "نعم" if user.get("is_joined_recently") else None},
        links=discover(user.get("biography"), user.get("external_url")),
    )


async def x_roblox(c, u, text):
    r = await c.post("https://users.roblox.com/v1/usernames/users",
                     json={"usernames": [u], "excludeBannedUsers": False}, headers=HEADERS, timeout=TIMEOUT)
    rid = dig(r.json() if r.status_code == 200 else None, "data", 0, "id")
    if not rid:
        return None
    d, fol, fing, thumb = await asyncio.gather(
        get_json(c, f"https://users.roblox.com/v1/users/{rid}"),
        get_json(c, f"https://friends.roblox.com/v1/users/{rid}/followers/count"),
        get_json(c, f"https://friends.roblox.com/v1/users/{rid}/followings/count"),
        get_json(c, f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={rid}&size=420x420&format=Png"),
    )
    d = d or {}
    return profile(
        name=d.get("displayName"), handle=d.get("name"), avatar=dig(thumb, "data", 0, "imageUrl"),
        bio=d.get("description"), joined=iso(d.get("created")), uid=rid,
        verified=d.get("hasVerifiedBadge"), followers=dig(fol, "count"), following=dig(fing, "count"),
        fields={"محظور": "نعم" if d.get("isBanned") else None},
        links=discover(d.get("description")),
    )


async def x_chess(c, u, text):
    d = await get_json(c, f"https://api.chess.com/pub/player/{u.lower()}")
    if not d or "username" not in d:
        return None
    return profile(
        name=d.get("name"), handle=d.get("username"), avatar=d.get("avatar"),
        followers=d.get("followers"), joined=iso(d.get("joined")), uid=d.get("player_id"),
        location=d.get("location"), verified=d.get("verified"),
        fields={"الدولة": (d.get("country") or "").rsplit("/", 1)[-1] or None, "اللقب": d.get("title"),
                "آخر ظهور": iso(d.get("last_online")), "الحالة": d.get("status")},
    )


async def x_lichess(c, u, text):
    d = await get_json(c, f"https://lichess.org/api/user/{u}")
    if not d or "id" not in d:
        return None
    pr = d.get("profile") or {}
    return profile(
        name=pr.get("realName") or " ".join(filter(None, [pr.get("firstName"), pr.get("lastName")])) or None,
        handle=d.get("username"), bio=pr.get("bio"), joined=iso(d.get("createdAt")),
        location=pr.get("location"), posts=dig(d, "count", "all"), posts_label="مباراة",
        fields={"الدولة": pr.get("flag") or pr.get("country"), "آخر ظهور": iso(d.get("seenAt")),
                "اللقب": d.get("title")},
        links=discover(pr.get("bio"), pr.get("links")),
    )


async def x_hackernews(c, u, text):
    d = await get_json(c, f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    if not d:
        return None
    about = re.sub(r"<[^>]+>", " ", htmllib.unescape(d.get("about") or "")).strip()
    return profile(handle=d.get("id"), bio=about, joined=iso(d.get("created")),
                   fields={"النقاط": d.get("karma"), "عدد المشاركات": len(d.get("submitted") or [])},
                   links=discover(about))


async def x_keybase(c, u, text):
    d = await get_json(c, f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}")
    them = dig(d, "them", 0)
    if not them:
        return None
    pr = them.get("profile") or {}
    proofs = dig(them, "proofs_summary", "all") or []
    links = [p.get("service_url") for p in proofs if p.get("service_url")]
    return profile(
        name=pr.get("full_name"), handle=dig(them, "basics", "username"), bio=pr.get("bio"),
        location=pr.get("location"), avatar=dig(them, "pictures", "primary", "url"),
        joined=iso(dig(them, "basics", "ctime")),
        fields={f"إثبات {p.get('proof_type')}": p.get("nametag") for p in proofs[:12]},
        links=links + discover(pr.get("bio")),
    )


async def x_dockerhub(c, u, text):
    d = await get_json(c, f"https://hub.docker.com/v2/users/{u}/")
    if not d or not d.get("username"):
        return None
    return profile(name=d.get("full_name"), handle=d.get("username"), avatar=d.get("gravatar_url"),
                   location=d.get("location"), joined=iso(d.get("date_joined")), website=d.get("profile_url"),
                   uid=d.get("id"), fields={"الشركة": d.get("company"), "النوع": d.get("type")})


async def x_bluesky(c, u, text):
    d = await get_json(c, f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social")
    if not d or "did" not in d:
        return None
    return profile(name=d.get("displayName"), handle=d.get("handle"), avatar=d.get("avatar"), banner=d.get("banner"),
                   bio=d.get("description"), followers=d.get("followersCount"), following=d.get("followsCount"),
                   posts=d.get("postsCount"), joined=iso(d.get("createdAt")), uid=d.get("did"),
                   links=discover(d.get("description")))


async def x_codeforces(c, u, text):
    d = await get_json(c, f"https://codeforces.com/api/user.info?handles={u}")
    r = dig(d, "result", 0)
    if not r:
        return None
    return profile(
        name=" ".join(filter(None, [r.get("firstName"), r.get("lastName")])) or None, handle=r.get("handle"),
        avatar=r.get("titlePhoto"), followers=r.get("friendOfCount"), joined=iso(r.get("registrationTimeSeconds")),
        location=", ".join(filter(None, [r.get("city"), r.get("country")])) or None,
        fields={"التصنيف": r.get("rank"), "النقاط": r.get("rating"), "أعلى نقاط": r.get("maxRating"),
                "المؤسسة": r.get("organization"), "آخر ظهور": iso(r.get("lastOnlineTimeSeconds"))},
    )


async def x_devto(c, u, text):
    d = await get_json(c, f"https://dev.to/api/users/by_username?url={u}")
    if not d or "username" not in d:
        return None
    return profile(name=d.get("name"), handle=d.get("username"), avatar=d.get("profile_image"),
                   bio=d.get("summary"), location=d.get("location"), joined=d.get("joined_at"),
                   website=d.get("website_url"), uid=d.get("id"),
                   fields={"تويتر": d.get("twitter_username"), "جيت هب": d.get("github_username")},
                   links=discover(d.get("summary"), d.get("website_url")))


async def x_duolingo(c, u, text):
    d = await get_json(c, f"https://www.duolingo.com/2017-06-30/users?username={u}")
    us = dig(d, "users", 0)
    if not us:
        return None
    pic = us.get("picture")
    langs = [x.get("title") for x in us.get("courses") or [] if x.get("title")]
    return profile(name=us.get("name"), handle=us.get("username"),
                   avatar=f"https:{pic}/xxlarge" if pic and pic.startswith("//") else pic,
                   bio=us.get("bio"), joined=iso(us.get("creationDate")), uid=us.get("id"),
                   fields={"أيام متتالية": us.get("streak"), "النقاط": us.get("totalXp"),
                           "يتعلم": "، ".join(langs[:6]) or None, "مشترك": "نعم" if us.get("hasPlus") else None})


async def x_reddit(c, u, text):
    d = await get_json(c, f"https://www.reddit.com/user/{u}/about.json")
    data = (d or {}).get("data")
    if not data:
        return None
    sub = data.get("subreddit") or {}
    return profile(
        name=sub.get("title"), handle=data.get("name"),
        avatar=(data.get("snoovatar_img") or data.get("icon_img") or "").split("?")[0] or None,
        banner=(sub.get("banner_img") or "").split("?")[0] or None, bio=sub.get("public_description"),
        followers=sub.get("subscribers"), joined=iso(data.get("created_utc")), uid=data.get("id"),
        verified=data.get("verified"),
        fields={"نقاط المنشورات": data.get("link_karma"), "نقاط التعليقات": data.get("comment_karma"),
                "موظف في ريديت": "نعم" if data.get("is_employee") else None,
                "مشرف": "نعم" if data.get("is_mod") else None},
        links=discover(sub.get("public_description")),
    )


async def x_steam(c, u, text):
    r = await c.get(f"https://steamcommunity.com/id/{u}/?xml=1", headers=HEADERS, timeout=TIMEOUT)
    t = r.text
    if "<steamID64>" not in t:
        return None
    g = lambda tag: (lambda m: htmllib.unescape(m.group(1)).strip() if m else None)(
        re.search(rf"<{tag}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{tag}>", t, re.S))
    return profile(name=g("realname") or g("steamID"), handle=u, avatar=g("avatarFull"), bio=g("summary"),
                   location=g("location"), joined=g("memberSince"), uid=g("steamID64"),
                   fields={"الاسم الظاهر": g("steamID"), "الحالة": g("stateMessage"),
                           "الخصوصية": g("privacyState"), "محظور تجاريًا": g("tradeBanState")})


async def x_kick(c, u, text):
    d = await get_json(c, f"https://kick.com/api/v2/channels/{u}")
    if not d or "user" not in d:
        return None
    us = d["user"]
    return profile(name=us.get("username"), handle=d.get("slug"), avatar=us.get("profile_pic"),
                   banner=dig(d, "banner_image", "url"), bio=us.get("bio"), followers=d.get("followers_count"),
                   verified=bool(d.get("verified")) or None, uid=us.get("id"),
                   fields={"مباشر الآن": "نعم" if d.get("livestream") else None,
                           "إنستقرام": us.get("instagram"), "تويتر": us.get("twitter"),
                           "يوتيوب": us.get("youtube"), "تيك توك": us.get("tiktok"), "ديسكورد": us.get("discord")},
                   links=discover(us.get("bio")))


async def x_linktree(c, u, text):
    if not text:
        r = await c.get(f"https://linktr.ee/{u}", headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        text = r.text
    data = json_script(text, "__NEXT_DATA__")
    acc = dig(data, "props", "pageProps", "account") or {}
    if not acc:
        return None
    links = [l.get("url") for l in (dig(data, "props", "pageProps", "links") or acc.get("links") or []) if l.get("url")]
    socials = [s.get("url") for s in acc.get("socialLinks") or [] if s.get("url")]
    return profile(name=acc.get("pageTitle") or acc.get("username"), handle=acc.get("username"),
                   avatar=acc.get("profilePictureUrl"), bio=acc.get("description"), uid=acc.get("id"),
                   fields={"عدد الروابط": len(links) or None},
                   links=(socials + links)[:20])


async def x_telegram(c, u, text):
    if not text:
        r = await c.get(f"https://t.me/{u}", headers=HEADERS, timeout=TIMEOUT)
        text = r.text
    meta = parse_meta(text)
    extra = re.search(r'<div class="tgme_page_extra">\s*(.*?)\s*</div>', text, re.S)
    extra = htmllib.unescape(re.sub(r"<[^>]+>", "", extra.group(1))).strip() if extra else None
    kind = None
    followers = None
    if extra:
        m = re.search(r"([\d\s]+)\s+(subscribers|members)", extra)
        if m:
            followers = to_int(m.group(1))
            kind = "قناة" if m.group(2) == "subscribers" else "مجموعة"
        elif extra.startswith("@"):
            kind = "مستخدم"
    if "tgme_page_extra" not in text and "bot" in u.lower():
        kind = "بوت"
    return profile(name=meta.get("og:title"), handle=u, avatar=meta.get("og:image"),
                   bio=meta.get("og:description"), followers=followers,
                   fields={"النوع": kind}, links=discover(meta.get("og:description")))


EXTRACTORS = {
    "GitHub": x_github, "GitLab": x_gitlab, "TikTok": x_tiktok, "Snapchat": x_snapchat,
    "Instagram": x_instagram, "Roblox": x_roblox, "Chess": x_chess, "Lichess": x_lichess,
    "HackerNews": x_hackernews, "Keybase": x_keybase, "Docker Hub": x_dockerhub, "Bluesky": x_bluesky,
    "Codeforces": x_codeforces, "DEV Community": x_devto, "Duolingo": x_duolingo, "Reddit": x_reddit,
    "Steam Community (User)": x_steam, "Kick": x_kick, "Linktree": x_linktree, "Telegram": x_telegram,
}


def generic_profile(text: str, username: str):
    """يستخرج بيانات عامة من وسوم الصفحة، ويقبلها فقط إذا كانت تخص هذا الحساب."""
    if not text or "<" not in text[:2000]:
        return None
    m = parse_meta(text)
    title = m.get("og:title") or m.get("twitter:title") or m.get("_title")
    desc = m.get("og:description") or m.get("twitter:description") or m.get("description")
    img = m.get("og:image") or m.get("twitter:image")
    u = username.lower()
    blob = " ".join(filter(None, [title, desc, m.get("og:url")])).lower()
    if u not in blob:
        return None
    nums = {}
    if desc:
        for n, label in re.findall(r"([\d.,]+\s?[KkMmBb]?)\s+(Followers|Following|Posts|Subscribers|Likes|Videos|Tracks)", desc):
            nums[label.lower()] = to_int(n)
    return profile(name=title, avatar=img, bio=desc,
                   followers=nums.get("followers") or nums.get("subscribers"),
                   following=nums.get("following"), posts=nums.get("posts") or nums.get("videos") or nums.get("tracks"),
                   likes=nums.get("likes"), links=discover(desc))


# ───────────── الفحص ─────────────

async def check_site(client, name, site, username, enrich=True):
    url = site["url"].replace("{}", username)
    res = {"site": name, "url": url, "home": site.get("urlMain", ""), "status": "none"}
    regex = site.get("regexCheck")
    if regex and not re.search(regex, username):
        res["status"] = "invalid"
        return res

    probe = site.get("urlProbe", site["url"]).replace("{}", username)
    etype = site["errorType"]
    method = site.get("request_method") or "GET"
    payload = fill(site.get("request_payload"), username)
    headers = {**HEADERS, **site.get("headers", {})}
    try:
        r = await client.request(method, probe, headers=headers, json=payload,
                                 follow_redirects=etype != "response_url", timeout=TIMEOUT)
    except Exception:
        res["status"] = "error"
        return res

    code = r.status_code
    if code in (403, 429, 503) and etype != "status_code":
        res["status"] = "error"  # حجب أو تحدٍّ أمني، لا نحكم بوجود الحساب
        return res
    text = r.text if "text" in r.headers.get("content-type", "") or "json" in r.headers.get("content-type", "") else ""

    if etype == "message":
        found = code < 400 and not any(msg in text for msg in as_list(site.get("errorMsg")))
    elif etype == "status_code":
        if code in (403, 429, 503):
            res["status"] = "error"
            return res
        found = not (code in as_list(site.get("errorCode")) or code >= 300 or code < 200)
    else:
        found = 200 <= code < 300

    res["status"] = "found" if found else "none"
    if found and enrich:
        page_text = text if probe == url or name in ("Instagram",) else None
        prof = None
        try:
            if name in EXTRACTORS:
                prof = await asyncio.wait_for(EXTRACTORS[name](client, username, page_text), TIMEOUT + 5)
            if not prof and page_text:
                prof = generic_profile(page_text, username)
        except Exception:
            prof = None
        if prof:
            res["profile"] = prof
    return res


# ───────────── المعايرة الذاتية ─────────────

CAL = {"started": None, "finished": None, "sites": {}}


def random_name(regex):
    for _ in range(50):
        n = "q" + "".join(random.choices(string.ascii_lowercase + string.digits, k=11))
        if not regex or re.search(regex, n):
            return n
    return "qx" + "".join(random.choices(string.ascii_lowercase, k=10))


async def calibrate():
    CAL["started"] = time.time()
    sem = asyncio.Semaphore(40)
    limits = httpx.Limits(max_connections=40)
    async with httpx.AsyncClient(limits=limits) as client:
        async def one(name, site):
            async with sem:
                claimed = site.get("username_claimed")
                if not claimed:
                    return name, "unknown"
                a = await check_site(client, name, site, claimed, enrich=False)
                b = await check_site(client, name, site, random_name(site.get("regexCheck")), enrich=False)
                if a["status"] == "found" and b["status"] == "none":
                    return name, "ok"
                if b["status"] == "found":
                    return name, "false_positive"
                if "error" in (a["status"], b["status"]):
                    return name, "blocked"
                return name, "false_negative"
        results = await asyncio.gather(*(one(n, s) for n, s in SITES.items()), return_exceptions=True)
    for r in results:
        if isinstance(r, tuple):
            CAL["sites"][r[0]] = r[1]
    CAL["finished"] = time.time()


async def calibrate_loop():
    while True:
        try:
            await calibrate()
        except Exception:
            pass
        await asyncio.sleep(CALIBRATE_EVERY)


@app.on_event("startup")
async def _startup():
    asyncio.create_task(calibrate_loop())


def active_sites():
    st = CAL["sites"]
    if not st or sum(v == "ok" for v in st.values()) < 50:  # معايرة فاشلة بالكامل؟ لا نعطّل كل شيء
        return dict(SITES)
    return {n: s for n, s in SITES.items() if st.get(n, "ok") in ("ok", "unknown")}


# ───────────── الواجهات ─────────────

@app.get("/")
async def index():
    return FileResponse(BASE / "index.html")


@app.get("/api/stats")
async def stats():
    return {"platforms": len(active_sites()), "total": len(SITES), "calibrated": CAL["finished"] is not None}


@app.get("/api/health")
async def health():
    counts = defaultdict(int)
    for v in CAL["sites"].values():
        counts[v] += 1
    by_status = defaultdict(list)
    for k, v in sorted(CAL["sites"].items()):
        by_status[v].append(k)
    return {
        "total": len(SITES), "active": len(active_sites()), "counts": counts,
        "started": CAL["started"], "finished": CAL["finished"], "sites": by_status,
    }


@app.get("/api/check")
async def check_one(site: str, u: str, request: Request):
    """فحص منصة واحدة مع البطاقة، للاختبار."""
    if site not in SITES or not USERNAME_RE.match(u):
        raise HTTPException(400, "bad input")
    if not rate_ok(client_ip(request)):
        raise HTTPException(429, "تجاوزت الحد المسموح")
    async with httpx.AsyncClient() as client:
        return await check_site(client, site, SITES[site], u)


@app.get("/api/search")
async def search(u: str, request: Request):
    username = u.strip().lstrip("@")
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم غير صالح")
    if not rate_ok(client_ip(request)):
        raise HTTPException(429, "تجاوزت الحد المسموح، حاول بعد قليل")
    sites = active_sites()

    async def stream():
        yield f"event: start\ndata: {json.dumps({'total': len(sites)})}\n\n"
        if username.lower() in BLOCKLIST:
            yield f"event: done\ndata: {json.dumps({'found': 0, 'blocked': True})}\n\n"
            return
        started = time.time()
        sem = asyncio.Semaphore(CONCURRENCY)
        limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=20)
        async with httpx.AsyncClient(limits=limits) as client:
            async def run(n, s):
                async with sem:
                    try:
                        return await check_site(client, n, s, username)
                    except Exception:
                        return {"site": n, "url": s["url"].replace("{}", username), "status": "error"}
            tasks = [asyncio.create_task(run(n, s)) for n, s in sites.items()]
            found = 0
            try:
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    found += res["status"] == "found"
                    yield f"event: result\ndata: {json.dumps(res, ensure_ascii=False)}\n\n"
                    if await request.is_disconnected():
                        break
            finally:
                for t in tasks:
                    t.cancel()
        yield f"event: done\ndata: {json.dumps({'found': found, 'seconds': round(time.time() - started, 1)})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
