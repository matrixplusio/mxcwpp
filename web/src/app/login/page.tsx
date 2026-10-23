"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { User, Lock } from "lucide-react";
import { authApi } from "@/lib/api/auth";
import { systemApi } from "@/lib/api/system";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/Button";
import { BRAND } from "@/lib/brand";

/** 自建的高保真产品预览(非真实截图,纯装饰示意) */
function ProductMockup() {
  const { t } = useTranslation();
  return (
    <motion.div
      initial={{ opacity: 0, y: 24, rotate: -2 }}
      animate={{ opacity: 1, y: 0, rotate: -2 }}
      transition={{ duration: 0.7, ease: "easeOut", delay: 0.3 }}
      className="w-[440px] rounded-2xl bg-surface shadow-2xl shadow-slate-900/10 ring-1 ring-border p-4"
    >
      <div className="flex items-center gap-2 mb-4">
        <div className="h-6 w-6 rounded-lg bg-gradient-to-br from-primary to-accent" />
        <div className="h-2 w-16 rounded-full bg-surface-muted" />
        <div className="ml-auto flex gap-1.5">
          <span className="h-2 w-2 rounded-full bg-surface-muted" />
          <span className="h-2 w-2 rounded-full bg-surface-muted" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-4">
        {[
          { v: "98.7", l: "login.mock.score", c: "from-emerald-400 to-emerald-500" },
          { v: "1,284", l: "login.mock.asset", c: "from-blue-400 to-blue-500" },
          { v: "12", l: "login.mock.high", c: "from-rose-400 to-rose-500" },
        ].map((k) => (
          <div key={k.l} className="rounded-xl border border-border p-3">
            <div className={`h-6 w-6 rounded-lg bg-gradient-to-br ${k.c} mb-2`} />
            <div className="text-base font-bold text-ink leading-none">{k.v}</div>
            <div className="text-[10px] text-faint mt-1">{t(k.l)}</div>
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-border p-3">
        <div className="h-2 w-20 rounded-full bg-surface-muted mb-3" />
        <svg viewBox="0 0 320 80" className="w-full h-20">
          <defs>
            <linearGradient id="mk" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#2563EB" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#2563EB" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d="M0 60 C 40 50, 70 20, 110 28 S 180 60, 220 38 S 290 8, 320 18 L 320 80 L 0 80 Z" fill="url(#mk)" />
          <path d="M0 60 C 40 50, 70 20, 110 28 S 180 60, 220 38 S 290 8, 320 18" fill="none" stroke="#2563EB" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </div>
    </motion.div>
  );
}

export default function LoginPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const setSession = useAuthStore((s) => s.setSession);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  // 站点配置为公开接口,登录前即可读取品牌(名称/Logo)
  const { data: site } = useQuery({ queryKey: ["site-config-public"], queryFn: () => systemApi.getSiteConfig() });
  const siteName = site?.site_name || "MXCWPP";
  const siteLogo = site?.site_logo || "/logo.png";

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setLoading(true);
    try {
      const res = await authApi.login({ username, password });
      setSession(res.token, res.user);
      router.push(res.need_change_password ? "/system" : "/dashboard");
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : t("login.failed"));
    } finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-[1.1fr_1fr]">
      {/* 左：品牌 + 产品预览 */}
      <div className="relative hidden lg:flex flex-col justify-between overflow-hidden p-12 text-ink">
        <div className="absolute inset-0 bg-gradient-to-br from-[#EAF1FE] via-[#F2F6FD] to-[#F4F8FC] dark:from-[#0F1521] dark:via-[#0B0F17] dark:to-[#131927]" />
        <div className="absolute -top-24 -left-24 h-96 w-96 rounded-full bg-primary/20 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-96 w-96 rounded-full bg-accent/20 blur-3xl" />

        <motion.div
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.05 }}
          className="relative flex items-center gap-3"
        >
          <img src={siteLogo} alt="logo" className="h-10 w-10 object-contain" />
          <span className="text-lg font-extrabold tracking-tight">{siteName}</span>
        </motion.div>

        <div className="relative flex flex-col items-start gap-8">
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.15 }}>
            <h1 className="text-4xl font-extrabold leading-tight tracking-tight max-w-md">
              {t("login.headline")}
            </h1>
            <p className="mt-4 text-base text-muted max-w-md">
              {t("login.subtitle")}
            </p>
          </motion.div>
          <ProductMockup />
        </div>

        <motion.div
          initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.45 }}
          className="relative flex flex-wrap gap-2"
        >
          {["Linux", "Kubernetes", "Docker", "eBPF", "MITRE ATT&CK"].map((t) => (
            <span key={t} className="rounded-full bg-surface/70 ring-1 ring-border px-3 py-1 text-xs font-medium text-muted backdrop-blur">{t}</span>
          ))}
        </motion.div>
      </div>

      {/* 右：登录表单 */}
      <div className="flex items-center justify-center p-8 bg-surface">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-sm"
        >
          <div className="lg:hidden mb-8 flex items-center gap-3">
            <img src={siteLogo} alt="logo" className="h-9 w-9 object-contain" />
            <span className="text-lg font-extrabold tracking-tight text-ink">{siteName}</span>
          </div>

          <h2 className="text-2xl font-bold text-ink">{t("login.consoleTitle")}</h2>
          <p className="mt-1 text-sm text-muted mb-8">{t("login.consoleDesc")}</p>

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-ink mb-1.5">{t("login.username")}</label>
              <div className="relative">
                <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t("login.usernamePlaceholder")}
                  className="w-full h-11 rounded-control border border-border bg-bg/50 pl-9 pr-3 text-sm text-ink outline-none transition-colors focus:border-primary focus:bg-surface focus:ring-4 focus:ring-primary/10"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1.5">{t("login.password")}</label>
              <div className="relative">
                <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t("login.passwordPlaceholder")}
                  className="w-full h-11 rounded-control border border-border bg-bg/50 pl-9 pr-3 text-sm text-ink outline-none transition-colors focus:border-primary focus:bg-surface focus:ring-4 focus:ring-primary/10"
                />
              </div>
            </div>
            {err && <p className="text-sm text-danger">{err}</p>}
            <Button type="submit" disabled={loading} className="w-full h-11 bg-gradient-to-r from-primary to-accent hover:opacity-95">
              {loading ? t("login.submitting") : t("login.submit")}
            </Button>
          </form>

          <p className="mt-8 text-center text-xs text-muted">{t("login.footer", { year: 2026, brand: BRAND })}</p>
        </motion.div>
      </div>
    </div>
  );
}
