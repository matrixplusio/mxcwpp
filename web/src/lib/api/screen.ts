import { get } from "./client";
import { TOKEN_KEY } from "./codes";

export type ScreenSeverity = "critical" | "high" | "medium" | "low";

export interface ScreenFeedItem {
  id: string;
  time: string;
  severity: ScreenSeverity;
  title: string;
  host: string;
}

export interface ScreenEngine {
  key: string;
  name: string;
  count: number;
  unit: string;
  status: "healthy" | "warn" | "down";
}

export interface ScreenOverview {
  kpi: {
    blockedToday: number;
    activeThreats: number;
    agentsOnline: number;
    agentsTotal: number;
    fpSuppressRate: number;
    postureScore: number;
  };
  engines: ScreenEngine[];
  severity: { critical: number; high: number; medium: number; low: number };
  trend: { hours: string[]; edr: number[]; bde: number[]; ml: number[] };
  hostRank: { name: string; score: number; issues: string }[];
  attck: { id: string; name: string; count: number }[];
  compliance: { criticalVuln: number; highVuln: number; baselineRate: number; kubeBaseline: number };
  feed: ScreenFeedItem[];
}

// 攻击地图数据源（P3）：入站连接（攻击面）+ IOC 命中（确认威胁）两层，均已 GeoIP 定位。
export interface AttackSource {
  name: string;
  country: string;
  coord: [number, number]; // [lng, lat]
  count: number;
}
export interface AttackSources {
  inbound: AttackSource[]; // 外网入站连接源（灰/黄底层）
  threats: AttackSource[]; // IOC 命中的恶意源（红点）
}

export const screenApi = {
  getOverview: () => get<ScreenOverview>("/screen/overview"),
  getAttackSources: () => get<AttackSources>("/screen/attack-sources"),
};

/**
 * streamScreenAlerts 以 fetch-stream 消费 SSE 告警流。
 * 不用 EventSource——它无法携带 Authorization 头，而鉴权走 JWT Bearer。
 */
export function streamScreenAlerts(onAlert: (a: ScreenFeedItem) => void, signal: AbortSignal): void {
  const token = typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
  fetch("/api/v1/screen/alerts/stream", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal,
  })
    .then(async (res) => {
      if (!res.body) return;
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";
        for (const p of parts) {
          const dataLine = p.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          try {
            onAlert(JSON.parse(dataLine.slice(5).trim()) as ScreenFeedItem);
          } catch {
            /* 忽略心跳/非法行 */
          }
        }
      }
    })
    .catch(() => {
      /* abort 或网络中断，由上层重连 */
    });
}
