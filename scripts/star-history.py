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
from datetime import date, datetime, timedelta

API = "https://api.github.com"
PER_PAGE = 100
MAX_PAGES = 100  # 上限 10000 star，够用且防翻页失控

# 配色跟随 GitHub 主题：SVG 内的 prefers-color-scheme 由浏览器解析，
# 查询不生效时落到浅色一套，背景保持透明，深色下也不会糊成一块。
LIGHT = {"text": "#1f2328", "muted": "#59636e", "grid": "#d1d9e0",
         "bg": "#ffffff", "border": "#d1d9e0"}
DARK = {"text": "#f0f6fc", "muted": "#9198a1", "grid": "#3d444d",
        "bg": "#0d1117", "border": "#3d444d"}
ACCENT = "#f0883e"

W, H = 840, 420
PAD_L, PAD_R, PAD_T, PAD_B = 56, 28, 76, 52
SAMPLES = 48  # 曲线采样点数：太密会把每颗 star 的台阶原样保留，失去平滑

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


def sample_series(stamps: list[datetime], first: date, last: date) -> list[tuple[float, int]]:
    """把「每颗 star 一个台阶」重采样成等距点，供平滑曲线用。

    直接连每颗 star 会画成锯齿楼梯，star 多了更是糊成一团；
    等距采样后曲线形状不变，但可以走平滑插值。
    """
    span = max((last - first).days, 1)
    days = [s.date() for s in stamps]
    pts: list[tuple[float, int]] = []
    idx = 0
    for i in range(SAMPLES + 1):
        t = span * i / SAMPLES
        cut = first + timedelta(days=t)
        while idx < len(days) and days[idx] <= cut:
            idx += 1
        pts.append((t, idx))
    return pts


def monotone_slopes(xs: list[float], ys: list[float]) -> list[float]:
    """Fritsch-Carlson 单调三次插值的斜率。

    star 累计数只增不减，普通样条会在陡增处冲出上界画出「先跌后涨」，
    这个方法保证插值同样单调。
    """
    n = len(xs)
    if n < 2:
        return [0.0] * n
    delta = [(ys[i + 1] - ys[i]) / (xs[i + 1] - xs[i]) for i in range(n - 1)]
    m = [delta[0]] + [(delta[i - 1] + delta[i]) / 2 for i in range(1, n - 1)] + [delta[-1]]
    for i in range(n - 1):
        if delta[i] == 0:
            m[i] = m[i + 1] = 0.0
            continue
        a, b = m[i] / delta[i], m[i + 1] / delta[i]
        h = a * a + b * b
        if h > 9:
            t = 3 / h**0.5
            m[i], m[i + 1] = t * a * delta[i], t * b * delta[i]
    return m


def curve_path(xs: list[float], ys: list[float]) -> str:
    """把采样点连成单调三次贝塞尔路径。"""
    m = monotone_slopes(xs, ys)
    d = [f"M {xs[0]:.1f} {ys[0]:.1f}"]
    for i in range(len(xs) - 1):
        dx = xs[i + 1] - xs[i]
        d.append(
            f"C {xs[i] + dx / 3:.1f} {ys[i] + m[i] * dx / 3:.1f}"
            f" {xs[i + 1] - dx / 3:.1f} {ys[i + 1] - m[i + 1] * dx / 3:.1f}"
            f" {xs[i + 1]:.1f} {ys[i + 1]:.1f}"
        )
    return " ".join(d)


def render(repo: str, stamps: list[datetime]) -> str:
    total = len(stamps)
    first, last = stamps[0].date(), date.today()
    span = max((last - first).days, 1)
    step = y_axis_step(total)
    y_max = step * 4

    def px(days: float) -> float:
        return PAD_L + days / span * (W - PAD_L - PAD_R)

    def py(v: float) -> float:
        return H - PAD_B - v / y_max * (H - PAD_T - PAD_B)

    pts = sample_series(stamps, first, last)
    xs = [px(t) for t, _ in pts]
    ys = [py(v) for _, v in pts]
    line = curve_path(xs, ys)
    base = py(0)

    css = (
        "<style>"
        f".t{{fill:{LIGHT['text']}}}.m{{fill:{LIGHT['muted']}}}.g{{stroke:{LIGHT['grid']}}}"
        f".bg{{fill:{LIGHT['bg']};stroke:{LIGHT['border']}}}"
        "@media (prefers-color-scheme:dark){"
        f".t{{fill:{DARK['text']}}}.m{{fill:{DARK['muted']}}}.g{{stroke:{DARK['grid']}}}"
        f".bg{{fill:{DARK['bg']};stroke:{DARK['border']}}}}}"
        "</style>"
    )

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f'font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif">',
        css,
        "<defs>"
        f'<linearGradient id="fade" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{ACCENT}" stop-opacity="0.30"/>'
        f'<stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/>'
        "</linearGradient></defs>",
        # 背景卡与文字同用一个媒体查询，两者永远同明同暗
        f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="10" class="bg" '
        f'stroke-width="1"/>',
        # 标题区：名字 + 小圆点图例，跟 star-history 的排版对齐
        f'<text x="{PAD_L}" y="34" class="t" font-size="17" font-weight="600">Star History</text>',
        f'<circle cx="{PAD_L + 5}" cy="52" r="4.5" fill="{ACCENT}"/>',
        f'<text x="{PAD_L + 17}" y="56" class="m" font-size="13">{repo}</text>',
        f'<text x="{W - PAD_R}" y="34" class="t" font-size="17" font-weight="600" '
        f'text-anchor="end">{total} ★</text>',
    ]

    for i in range(5):
        v = step * i
        y = py(v)
        out.append(
            f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{W - PAD_R}" y2="{y:.1f}" class="g" '
            f'stroke-width="1" stroke-opacity="{0.9 if i == 0 else 0.55}"'
            f'{"" if i == 0 else " stroke-dasharray=\"3 4\""}/>'
        )
        out.append(
            f'<text x="{PAD_L - 12}" y="{y + 4:.1f}" class="m" font-size="12" '
            f'text-anchor="end">{v}</text>'
        )

    last_label_x = float("-inf")
    for t in month_ticks(first, last):
        x = px((t - first).days)
        anchor = "middle"
        if x < PAD_L + 26:
            anchor, x = "start", PAD_L
        elif x > W - PAD_R - 26:
            anchor, x = "end", W - PAD_R
        if x - last_label_x < 62:
            continue
        last_label_x = x
        out.append(
            f'<text x="{x:.1f}" y="{H - PAD_B + 22}" class="m" font-size="12" '
            f'text-anchor="{anchor}">{t.strftime("%Y-%m")}</text>'
        )

    out.append(f'<path d="{line} L {xs[-1]:.1f} {base:.1f} L {xs[0]:.1f} {base:.1f} Z" fill="url(#fade)"/>')
    out.append(
        f'<path d="{line}" fill="none" stroke="{ACCENT}" stroke-width="2.5" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
    )
    out.append(f'<circle cx="{xs[-1]:.1f}" cy="{ys[-1]:.1f}" r="4" fill="{ACCENT}"/>')
    out.append(
        f'<text x="{W - PAD_R}" y="{H - 14}" class="m" font-size="11" '
        f'text-anchor="end" opacity="0.75">更新于 {last.isoformat()}</text>'
    )
    out.append("</svg>")
    return "\n".join(out) + "\n"


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
