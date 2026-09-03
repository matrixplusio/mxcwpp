import type { Metadata } from "next";
import { ScreenBackground } from "@/components/screen/ScreenBackground";

export const metadata: Metadata = {
  title: "态势感知大屏 · 矩阵云安全",
};

// 态势感知大屏为独立全屏路由，脱离 (console) 侧栏/顶栏 chrome，强制深色墙屏视觉。
export default function ScreenLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="screen-root relative min-h-screen w-full overflow-hidden bg-[#04070F] text-slate-100 antialiased">
      <ScreenBackground />
      <div className="relative z-10 h-screen">{children}</div>
    </div>
  );
}
