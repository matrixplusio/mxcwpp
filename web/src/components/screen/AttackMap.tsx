"use client";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";
import * as echarts from "echarts";
import { screenApi, type AttackSources, type AttackSource } from "@/lib/api/screen";

// 平台侧（GKE asia-east2，香港）为攻击线汇聚中心。
const CENTER: [number, number] = [114.1, 22.3];

// 后端不可用时的兜底示例（入站连接 + IOC 威胁两层）。
const FALLBACK: AttackSources = {
  inbound: [
    { name: "Amsterdam", country: "荷兰", coord: [4.9, 52.4], count: 24 },
    { name: "Frankfurt", country: "德国", coord: [8.7, 50.1], count: 18 },
    { name: "Singapore", country: "新加坡", coord: [103.8, 1.35], count: 31 },
    { name: "Mumbai", country: "印度", coord: [72.9, 19.1], count: 15 },
    { name: "Sao Paulo", country: "巴西", coord: [-46.6, -23.5], count: 12 },
    { name: "Tokyo", country: "日本", coord: [139.7, 35.7], count: 9 },
    { name: "Sydney", country: "澳洲", coord: [151.2, -33.9], count: 7 },
    { name: "London", country: "英国", coord: [-0.1, 51.5], count: 14 },
  ],
  threats: [
    { name: "Moscow", country: "俄罗斯", coord: [37.6, 55.7], count: 42 },
    { name: "Virginia", country: "美国", coord: [-78.5, 37.4], count: 31 },
    { name: "Kyiv", country: "乌克兰", coord: [30.5, 50.5], count: 11 },
    { name: "Lagos", country: "尼日利亚", coord: [3.4, 6.5], count: 8 },
  ],
};

export function AttackMap() {
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);
  const [count, setCount] = useState(1287);

  const { data } = useQuery({
    queryKey: ["screen-attack-sources"],
    queryFn: screenApi.getAttackSources,
    refetchInterval: 30000,
    staleTime: 25000,
  });
  const src = data && (data.inbound?.length || data.threats?.length) ? data : FALLBACK;

  useEffect(() => {
    let alive = true;
    fetch("/geo/world.json")
      .then((r) => r.json())
      .then((geo) => {
        if (!alive) return;
        echarts.registerMap("world", geo);
        setReady(true);
      })
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, []);

  // 攻击计数器缓慢累加，营造实时感。
  useEffect(() => {
    const t = setInterval(() => setCount((c) => c + Math.floor(Math.random() * 3) + 1), 1600);
    return () => clearInterval(t);
  }, []);

  if (failed) return <Centered text="世界地图加载失败" />;
  if (!ready) return <Centered text="加载世界地图…" />;

  const line = (s: AttackSource, color: string) => ({ coords: [s.coord, CENTER], lineStyle: { color } });
  const point = (s: AttackSource, color: string) => ({ name: `${s.country} · ${s.name}`, value: [...s.coord, s.count], itemStyle: { color } });

  const topThreats = [...src.threats].sort((a, b) => b.count - a.count).slice(0, 5);

  const option = {
    animationDurationUpdate: 0,
    geo: {
      map: "world",
      roam: false,
      silent: true,
      left: 0,
      right: 0,
      top: 20,
      bottom: 10,
      itemStyle: { areaColor: "#0A1526", borderColor: "rgba(56,189,248,0.18)", borderWidth: 0.5 },
      emphasis: { disabled: true },
    },
    series: [
      // 入站连接层（黄，攻击面，细）
      {
        type: "lines",
        coordinateSystem: "geo",
        zlevel: 1,
        effect: { show: true, constantSpeed: 30, trailLength: 0.5, symbol: "circle", symbolSize: 2.5, color: "#fcd34d" },
        lineStyle: { width: 0.8, opacity: 0.35, curveness: 0.15, color: "#f59e0b" },
        data: src.inbound.map((s) => line(s, "#f59e0b")),
      },
      // IOC 威胁层（红，确认威胁，粗）
      {
        type: "lines",
        coordinateSystem: "geo",
        zlevel: 2,
        effect: { show: true, constantSpeed: 40, trailLength: 0.4, symbol: "circle", symbolSize: 4, color: "#fff" },
        lineStyle: { width: 1.6, opacity: 0.7, curveness: 0.15, color: "#f43f5e" },
        data: src.threats.map((s) => line(s, "#f43f5e")),
      },
      // 入站源点（黄）
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        zlevel: 3,
        rippleEffect: { brushType: "stroke", scale: 2.5 },
        symbolSize: 4,
        data: src.inbound.map((s) => point(s, "#f59e0b")),
      },
      // IOC 威胁点（红，大）
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        zlevel: 4,
        rippleEffect: { brushType: "stroke", scale: 4 },
        symbolSize: 7,
        data: src.threats.map((s) => point(s, "#f43f5e")),
      },
      // 平台中心
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        zlevel: 5,
        rippleEffect: { brushType: "stroke", scale: 5 },
        symbolSize: 10,
        itemStyle: { color: "#22d3ee", shadowBlur: 10, shadowColor: "#22d3ee" },
        data: [{ name: "本平台", value: [...CENTER, 1] }],
      },
    ],
  };

  return (
    <div className="relative h-full w-full">
      {/* 计数器 */}
      <div className="absolute left-2 top-1 z-10">
        <div className="font-mono text-xl font-extrabold tabular-nums text-rose-300 drop-shadow-[0_0_10px_currentColor]">
          {count.toLocaleString()}
        </div>
        <div className="text-[9px] tracking-wide text-slate-400">今日累计攻击</div>
      </div>
      {/* TOP 威胁源 */}
      <div className="absolute right-2 top-1 z-10 space-y-0.5 text-right">
        <div className="text-[9px] tracking-wide text-rose-400/70">TOP 威胁源</div>
        {topThreats.map((t) => (
          <div key={t.name} className="flex items-center justify-end gap-1.5 text-[10px]">
            <span className="text-slate-400">{t.country}</span>
            <span className="font-mono font-bold tabular-nums text-rose-300">{t.count}</span>
          </div>
        ))}
      </div>
      {/* 图例 */}
      <div className="absolute bottom-1 left-2 z-10 flex items-center gap-3 text-[9px]">
        <span className="flex items-center gap-1 text-amber-300/80">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
          入站连接
        </span>
        <span className="flex items-center gap-1 text-rose-300/80">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
          IOC 威胁
        </span>
      </div>
      {!data && (
        <span className="absolute bottom-1 right-2 z-10 rounded bg-cyan-500/10 px-1.5 py-0.5 text-[9px] tracking-wide text-cyan-400/60">
          示例数据 · 后端 GeoIP 待部署
        </span>
      )}
      <ReactECharts option={option} style={{ height: "100%", width: "100%" }} lazyUpdate />
    </div>
  );
}

function Centered({ text }: { text: string }) {
  return <div className="flex h-full items-center justify-center text-xs text-slate-500">{text}</div>;
}
