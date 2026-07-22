#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фид календаря групповых событий VRChat для мира 5ul.

Логинится бот-аккаунтом в VRChat API, забирает события календаря каждой
группы из groups.json (текущий + следующий месяц), обрезает лишнее и пишет
компактный docs/events.json для GitHub Pages. Мир читает его через
VRCStringDownloader (*.github.io — доверенный домен String Loading).

Секреты (env): VRC_USERNAME, VRC_PASSWORD, VRC_TOTP_SECRET, VRC_CONTACT.
Кука сессии хранится в state/cookies.json и переиспользуется между
запусками — повторные логины съедают лимит одновременных сессий VRChat.

Правила игры с неофициальным API: внятный User-Agent с контактом,
темп ~1 запрос в несколько секунд, бэкофф на 429. Нарушение — риск бана.
"""

import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pyotp
import requests

API = "https://api.vrchat.cloud/api/1"
STATE_DIR = "state"
COOKIES_PATH = os.path.join(STATE_DIR, "cookies.json")
OUT_PATH = os.path.join("docs", "events.json")
GROUPS_PATH = "groups.json"

USERNAME = os.environ.get("VRC_USERNAME", "")
PASSWORD = os.environ.get("VRC_PASSWORD", "")
TOTP_SECRET = os.environ.get("VRC_TOTP_SECRET", "")
CONTACT = os.environ.get("VRC_CONTACT", "no-contact-set@example.com")

USER_AGENT = "FiveUlCalendarFeed/1.0 " + CONTACT

# Горизонт: прошедшие события старше 3 часов выбрасываем, дальше 35 дней — тоже.
PAST_GRACE = timedelta(hours=3)
HORIZON = timedelta(days=35)
DESC_LIMIT = 280
HEARTBEAT = timedelta(hours=6)  # обновлять gen даже без изменений — маркер живости фида

# Символы, запечённые в TMP-атлас мира (см. CalendarSetup.CAL_CHARS).
# Всё вне набора заменяем пробелом, чтобы в панели не было «квадратов».
ALLOWED_CHARS = set(
    "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789 .,:;!?()[]{}+-<>=/*%\"'#&_|\\—–«»→•№…\n"
)


def log(msg):
    print("[feed] " + msg, flush=True)


def die(msg):
    log("ОШИБКА: " + msg)
    sys.exit(1)


def clean_text(text, limit, keep_newlines):
    if not text:
        return ""
    out = []
    for ch in text:
        if ch == "\r":
            continue
        if ch == "\n" and not keep_newlines:
            ch = " "
        out.append(ch if ch in ALLOWED_CHARS else " ")
    result = "".join(out)
    while "  " in result:
        result = result.replace("  ", " ")
    result = result.strip()
    if len(result) > limit:
        result = result[: limit - 1].rstrip() + "…"
    return result


# ---------------------------------------------------------------- сессия --

def load_session():
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    if os.path.exists(COOKIES_PATH):
        try:
            with open(COOKIES_PATH, "r", encoding="utf-8") as f:
                for name, value in json.load(f).items():
                    s.cookies.set(name, value, domain="api.vrchat.cloud")
            log("кука сессии восстановлена из state/")
        except Exception as e:  # noqa: BLE001 — битый стейт не должен валить фид
            log("не удалось прочитать куки (" + str(e) + "), логинимся заново")
    return s


def save_session(s):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(COOKIES_PATH, "w", encoding="utf-8") as f:
        json.dump(requests.utils.dict_from_cookiejar(s.cookies), f)


def session_alive(s):
    r = s.get(API + "/auth/user", timeout=30)
    if r.status_code != 200:
        return False
    body = r.json()
    return "requiresTwoFactorAuth" not in body


def login(s):
    if not USERNAME or not PASSWORD:
        die("VRC_USERNAME/VRC_PASSWORD не заданы (secrets репозитория)")
    log("логин по паролю (кука отсутствует или протухла)")
    creds = quote(USERNAME, safe="") + ":" + quote(PASSWORD, safe="")
    auth = base64.b64encode(creds.encode("utf-8")).decode("ascii")
    r = s.get(API + "/auth/user",
              headers={"Authorization": "Basic " + auth}, timeout=30)
    if r.status_code == 401:
        die("401 на логине — неверные логин/пароль или Cloudflare-блок: " + r.text[:200])
    r.raise_for_status()
    body = r.json()
    if "requiresTwoFactorAuth" in body:
        methods = body["requiresTwoFactorAuth"]
        if "totp" not in methods and "otp" not in methods:
            die("аккаунт требует 2FA методом " + str(methods) +
                " — включите TOTP (authenticator app) и положите секрет в VRC_TOTP_SECRET")
        if not TOTP_SECRET:
            die("нужен VRC_TOTP_SECRET (base32-секрет из настройки 2FA)")
        code = pyotp.TOTP(TOTP_SECRET.replace(" ", "")).now()
        r2 = s.post(API + "/auth/twofactorauth/totp/verify",
                    json={"code": code}, timeout=30)
        if r2.status_code != 200:
            die("TOTP не принят: " + r2.text[:200])
        if not session_alive(s):
            die("после 2FA сессия так и не поднялась")
    save_session(s)
    log("логин успешен, кука сохранена")


# ------------------------------------------------------------- календарь --

def month_start(dt):
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def fetch_group_month(s, group_id, month_dt):
    """Одна страница календаря группы за месяц. None => 401 (нужен релогин)."""
    params = {
        "date": month_dt.strftime("%Y-%m-%dT00:00:00.000Z"),
        "n": 100,
    }
    for attempt in (1, 2):
        r = s.get(API + "/calendar/" + group_id, params=params, timeout=30)
        if r.status_code == 401:
            return None
        if r.status_code == 429:
            if attempt == 1:
                log("429 от API — пауза 65 с")
                time.sleep(65)
                continue
            die("повторный 429 — снизьте частоту cron")
        if r.status_code == 404:
            log("группа " + group_id + " не найдена (404) — проверьте id")
            return []
        r.raise_for_status()
        return r.json().get("results", [])
    return []


def parse_iso(ts):
    # '2026-07-22T04:00:00.000Z' -> aware datetime
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def collect(s, cfg):
    now = datetime.now(timezone.utc)
    m1 = month_start(now)
    m2 = month_start(m1 + timedelta(days=32))
    out_groups = []
    relogged = False

    for grp in cfg["groups"]:
        gid = grp["id"].strip()
        seen = {}
        for month in (m1, m2):
            results = fetch_group_month(s, gid, month)
            if results is None:
                if relogged:
                    die("401 повторился после релогина")
                relogged = True
                login(s)
                results = fetch_group_month(s, gid, month)
                if results is None:
                    die("401 сразу после успешного логина")
            for ev in results:
                seen[ev.get("id", str(len(seen)))] = ev
            time.sleep(3)  # вежливый темп

        events = []
        for ev in seen.values():
            if ev.get("isDraft"):
                continue
            try:
                starts = parse_iso(ev["startsAt"])
                ends = parse_iso(ev["endsAt"])
            except (KeyError, ValueError):
                continue
            if ends < now - PAST_GRACE:
                continue
            if starts > now + HORIZON:
                continue
            platforms = ev.get("platforms") or []
            events.append({
                "t": clean_text(ev.get("title", ""), 80, False),
                "d": clean_text(ev.get("description", ""), DESC_LIMIT, True),
                "s": int(starts.timestamp()),
                "e": int(ends.timestamp()),
                "acc": ev.get("accessType", "public"),
                "cnt": int(ev.get("interestedUserCount") or 0),
                "q": 1 if "android" in platforms else 0,
            })
        events.sort(key=lambda e: e["s"])
        out_groups.append({
            "id": gid,
            "name": grp.get("name", gid),
            "events": events,
        })
        log(gid + ": событий в горизонте — " + str(len(events)))

    return out_groups


# ------------------------------------------------------------------ main --

def content_hash(groups):
    return hashlib.sha256(
        json.dumps(groups, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def main():
    with open(GROUPS_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("groups"):
        die("groups.json пуст — добавьте хотя бы одну группу")

    s = load_session()
    if not session_alive(s):
        login(s)
    else:
        log("сессия жива, логин не нужен")
        save_session(s)

    groups = collect(s, cfg)
    now_unix = int(time.time())
    payload = {"gen": now_unix, "groups": groups}

    # Не трогаем файл, если события не изменились и heartbeat свежий —
    # меньше пустых коммитов в репозитории.
    if os.path.exists(OUT_PATH):
        try:
            with open(OUT_PATH, "r", encoding="utf-8") as f:
                old = json.load(f)
            same = content_hash(old.get("groups", [])) == content_hash(groups)
            fresh = now_unix - int(old.get("gen", 0)) < HEARTBEAT.total_seconds()
            if same and fresh:
                log("изменений нет, heartbeat свежий — файл не переписываем")
                return
        except Exception:  # noqa: BLE001
            pass

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
    total = sum(len(g["events"]) for g in groups)
    log("записан " + OUT_PATH + ": групп " + str(len(groups)) +
        ", событий " + str(total))


if __name__ == "__main__":
    main()
