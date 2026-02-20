from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Tuple


CN_NUM = {
    "一": 1,
    "二": 2,
    "两": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}


def parse_cn_number(token: str) -> int | None:
    if token.isdigit():
        return int(token)
    if token in CN_NUM:
        return CN_NUM[token]
    if token.startswith("十") and len(token) == 2 and token[1] in CN_NUM:
        return 10 + CN_NUM[token[1]]
    if len(token) == 2 and token[0] in CN_NUM and token[1] == "十":
        return CN_NUM[token[0]] * 10
    if len(token) == 3 and token[0] in CN_NUM and token[1] == "十" and token[2] in CN_NUM:
        return CN_NUM[token[0]] * 10 + CN_NUM[token[2]]
    return None


def _day_range(target: datetime) -> Tuple[int, int]:
    start = target.replace(hour=0, minute=0, second=0, microsecond=0)
    end = target.replace(hour=23, minute=59, second=59, microsecond=0)
    return int(start.timestamp()), int(end.timestamp())


def parse_time_range(text: str | None) -> tuple[int, int]:
    now = datetime.now()
    if not text:
        start = now - timedelta(days=7)
        end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        return int(start.timestamp()), int(end.timestamp())

    raw = text.strip()

    if raw in {"今天", "今日"}:
        return _day_range(now)
    if raw == "昨天":
        return _day_range(now - timedelta(days=1))
    if raw in {"本周", "这周"}:
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        return int(start.timestamp()), int(end.timestamp())
    if raw in {"本月", "这个月"}:
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        return int(start.timestamp()), int(end.timestamp())

    explicit = re.search(r"(\d{4}-\d{1,2}-\d{1,2})\s*(?:到|至|-)\s*(\d{4}-\d{1,2}-\d{1,2})", raw)
    if explicit:
        start_dt = datetime.strptime(explicit.group(1), "%Y-%m-%d")
        end_dt = datetime.strptime(explicit.group(2), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
        return int(start_dt.timestamp()), int(end_dt.timestamp())

    m = re.search(r"(?:最近|过去|近)(\d+|[一二两三四五六七八九十]+)(天|小时|分钟)", raw)
    if m:
        n = parse_cn_number(m.group(1))
        unit = m.group(2)
        if not n:
            n = 7
        if unit == "天":
            start = now - timedelta(days=n)
        elif unit == "小时":
            start = now - timedelta(hours=n)
        else:
            start = now - timedelta(minutes=n)
        end = now
        return int(start.timestamp()), int(end.timestamp())

    shortcuts = {
        "最近三天": timedelta(days=3),
        "近三天": timedelta(days=3),
        "最近7天": timedelta(days=7),
        "近一周": timedelta(days=7),
        "最近24小时": timedelta(hours=24),
    }
    if raw in shortcuts:
        start = now - shortcuts[raw]
        return int(start.timestamp()), int(now.timestamp())

    # fallback: 默认最近7天
    start = now - timedelta(days=7)
    end = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return int(start.timestamp()), int(end.timestamp())
