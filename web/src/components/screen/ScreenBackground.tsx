"use client";
import { motion } from "framer-motion";

/** 大屏氛围背景：科技网格 + 角落辉光 + 暗角 + 扫描线，营造纵深感。 */
export function ScreenBackground() {
  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      {/* 科技网格 */}
      <div
        className="absolute inset-0 opacity-[0.5]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(56,189,248,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.05) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          maskImage: "radial-gradient(ellipse 80% 70% at 50% 40%, #000 40%, transparent 100%)",
        }}
      />
      {/* 角落辉光 */}
      <div className="absolute -left-40 -top-40 h-[520px] w-[520px] rounded-full bg-cyan-500/10 blur-[120px]" />
      <div className="absolute -right-40 top-1/3 h-[480px] w-[480px] rounded-full bg-violet-600/10 blur-[120px]" />
      <div className="absolute -bottom-40 left-1/3 h-[440px] w-[440px] rounded-full bg-blue-600/8 blur-[120px]" />
      {/* 暗角 */}
      <div
        className="absolute inset-0"
        style={{ background: "radial-gradient(ellipse 90% 80% at 50% 45%, transparent 55%, rgba(2,4,10,0.85) 100%)" }}
      />
      {/* 扫描线 */}
      <motion.div
        className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-cyan-400/[0.04] to-transparent"
        animate={{ y: ["-10%", "110%"] }}
        transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
      />
    </div>
  );
}
