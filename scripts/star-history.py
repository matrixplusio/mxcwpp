#!/usr/bin/env python3
"""生成 star 历史曲线 SVG。

GitHub 2026 年起把 stargazers 接口收成需要认证（未认证请求 401），
第三方 star history 服务因此普遍失效，且会要求用户交出带写权限的 PAT。
这个脚本改用 Actions 内置的 GITHUB_TOKEN——仓库级、单次运行后失效，
不需要任何长期凭据，也不把仓库数据交给第三方。

用法：
    GITHUB_TOKEN=xxx python3 scripts/star-history.py <owner/repo> <输出路径>

仅用标准库，无第三方依赖。
"""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime

API = "https://api.github.com"
PER_PAGE = 100
MAX_PAGES = 100  # 上限 10000 star，够用且防翻页失控

# 颜色在 GitHub 的浅色与深色主题下都要可读，因此不设背景，
# 文字与网格用中性灰，曲线用不依赖背景色的橙色。
COLOR_LINE = "#f0883e"
COLOR_TEXT = "#8b949e"
COLOR_GRID = "#8b949e"

W, H = 800, 400
PAD_L, PAD_R, PAD_T, PAD_B = 60, 24, 48, 48


def fetch_stargazers(repo: str, token: str) -> list[datetime]:
    """按时间顺序返回每个 star 的时间戳。"""
    stamps: list[datetime] = []
    for page in range(1, MAX_PAGES + 1):
        url = f"{API}/repos/{repo}/stargazers?per_page={PER_PAGE}&page={page}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.star+json")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.load(resp)
        except urllib.error.HTTPError as e:
            # 401/403 说明 token 不足以读 stargazers，直接报清楚，不要静默出空图
            sys.exit(f"读取 stargazers 失败（HTTP {e.code}）：{e.reason}")
        if not batch:
            break
        for item in batch:
            stamps.append(datetime.strptime(item["starred_at"], "%Y-%m-%dT%H:%M:%SZ"))
        if len(batch) < PER_PAGE:
            break
    stamps.sort()
    return stamps


def month_ticks(start: date, end: date) -> list[date]:
    """每个自然月一个刻度，超过 8 个则隔月取。"""
    ticks = []
    y, m = start.year, start.month
    while date(y, m, 1) <= end:
        if date(y, m, 1) >= start:  # 首颗 star 之前的月份不画
            ticks.append(date(y, m, 1))
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    if len(ticks) > 8:
        step = len(ticks) // 8 + 1
        ticks = ticks[::step]
    return ticks


def y_axis_step(total: int) -> int:
    """选一个刻度步长：4 格盖住 total，且步长本身是个整数好读数。"""
    step = -(-total // 4)  # 向上取整
    if step <= 5:
        return step
    if step <= 10:
        return 10
    for unit in (5, 25, 100, 500):
        if step <= unit * 10:
            return -(-step // unit) * unit
    return -(-step // 1000) * 1000


def render(repo: str, stamps: list[datetime]) -> str:
    total = len(stamps)
    first, last = stamps[0].date(), date.today()
    span = max((last - first).days, 1)
    step = y_axis_step(total)
    y_max = step * 4

    def px(d: date) -> float:
        return PAD_L + (d - first).days / span * (W - PAD_L - PAD_R)

    def py(v: int) -> float:
        return H - PAD_B - v / y_max * (H - PAD_T - PAD_B)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">',
        f'<text x="{PAD_L}" y="28" fill="{COLOR_TEXT}" font-size="15" font-weight="600">'
        f"{repo} — {total} stars</text>",
    ]

    # Y 轴网格与刻度
    for i in range(5):
        v = step * i
        y = py(v)
        parts.append(
            f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{W - PAD_R}" y2="{y:.1f}" '
            f'stroke="{COLOR_GRID}" stroke-opacity="0.2" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{PAD_L - 10}" y="{y + 4:.1f}" fill="{COLOR_TEXT}" '
            f'font-size="12" text-anchor="end">{v}</text>'
        )

    # X 轴月份刻度
    last_label_x = float("-inf")
    for t in month_ticks(first, last):
        x = px(t)
        # 贴边的标签改锚点，否则会被画布裁掉
        anchor = "middle"
        if x < PAD_L + 24:
            anchor, x = "start", PAD_L
        elif x > W - PAD_R - 24:
            anchor, x = "end", W - PAD_R
        if x - last_label_x < 56:  # 夹太近的两个月份会叠在一起，丢掉后一个
            continue
        last_label_x = x
        parts.append(
            f'<text x="{x:.1f}" y="{H - PAD_B + 20}" fill="{COLOR_TEXT}" '
            f'font-size="12" text-anchor="{anchor}">{t.strftime("%Y-%m")}</text>'
        )

    # 累计曲线：每颗 star 一个台阶，末端补到今天
    pts = [f"{px(first):.1f},{py(0):.1f}"]
    for i, s in enumerate(stamps, start=1):
        x = px(s.date())
        pts.append(f"{x:.1f},{py(i - 1):.1f}")
        pts.append(f"{x:.1f},{py(i):.1f}")
    pts.append(f"{px(last):.1f},{py(total):.1f}")
    parts.append(
        f'<polyline fill="none" stroke="{COLOR_LINE}" stroke-width="2" '
        f'stroke-linejoin="round" points="{" ".join(pts)}"/>'
    )

    parts.append(
        f'<text x="{W - PAD_R}" y="{H - 12}" fill="{COLOR_TEXT}" font-size="11" '
        f'text-anchor="end">更新于 {last.isoformat()}</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    repo, out_path = sys.argv[1], sys.argv[2]
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        sys.exit("缺少 GITHUB_TOKEN：stargazers 接口自 2026 年起必须认证")

    stamps = fetch_stargazers(repo, token)
    if not stamps:
        sys.exit("该仓库还没有 star，不生成图")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render(repo, stamps))
    print(f"{out_path}：{len(stamps)} stars，首颗 {stamps[0].date()}")


if __name__ == "__main__":
    main()
