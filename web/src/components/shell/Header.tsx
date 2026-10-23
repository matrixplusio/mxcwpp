"use client";
import { useState } from "react";
import { Info, Check, X, ExternalLink, Mail, User, Moon, Sun, Languages } from "lucide-react";
import { useTranslation } from "react-i18next";
import { NotificationBell } from "./NotificationBell";
import { UserMenu } from "./UserMenu";
import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useSiteStore } from "@/stores/site-config";
import { useThemeStore } from "@/stores/theme";
import { systemApi } from "@/lib/api/system";
import { MENUS } from "@/config/menu";
import { BRAND } from "@/lib/brand";
import { setLang } from "@/lib/i18n";
import { Modal } from "@/components/ui/Modal";
import { StatusTag } from "@/components/ui/Tag";

const LICENSE_ALLOW = ["allow1", "allow2", "allow3", "allow4", "allow5"] as const;
const LICENSE_DENY = ["deny1"] as const;

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="shrink-0 text-muted">{label}</span>
      <span className="min-w-0 truncate text-right font-medium text-ink">{value}</span>
    </div>
  );
}

function AboutModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const siteName = useSiteStore((s) => s.siteName);
  const logo = useSiteStore((s) => s.logo);
  const { data: ver } = useQuery({ queryKey: ["sys-version"], queryFn: () => systemApi.version(), enabled: open });
  const verText = ver?.version ? `v${ver.version}` : "—";

  return (
    <Modal open={open} onClose={onClose} title={t("about.title")} width={600}>
      <div className="max-h-[72vh] space-y-5 overflow-y-auto pr-1">
        {/* 版本横幅 */}
        <div className="flex flex-col items-center gap-2 rounded-card bg-surface-muted py-5 text-center">
          <img src={logo || "/logo.png"} alt="logo" className="h-14 w-14 object-contain" />
          <div className="mt-1 flex items-center gap-2">
            <span className="text-lg font-bold text-ink">{siteName}</span>
            <StatusTag tone="success">{t("about.community")}</StatusTag>
          </div>
          <div className="text-xs text-muted">{verText} · AGPL-3.0 · {t("about.openSourceTag")}</div>
        </div>

        {/* 版本信息 */}
        <section>
          <div className="mb-1.5 flex items-center gap-2 text-sm font-semibold text-ink"><Info size={15} className="text-primary" />{t("about.versionInfo")}</div>
          <div className="rounded-card border border-border px-4 py-1">
            <Row label={t("about.product")} value={`${siteName}(${t("about.productSuffix", { brand: BRAND })})`} />
            <Row label={t("about.version")} value={`${verText} ${t("about.versionSuffix")}`} />
            <Row label={t("about.service")} value={<span className="font-mono">{ver?.component ?? "—"}</span>} />
            <Row label={t("about.license")} value="AGPL-3.0" />
            <Row label={t("about.architecture")} value={t("about.architectureValue")} />
            <Row label={t("about.brand")} value={BRAND} />
          </div>
        </section>

        {/* 授权说明 */}
        <section>
          <div className="mb-1.5 text-sm font-semibold text-ink">{t("about.licenseTerms")}</div>
          <div className="space-y-2 rounded-card border border-border p-4">
            {LICENSE_ALLOW.map((k) => (
              <div key={k} className="flex gap-2 text-sm text-muted">
                <Check size={16} className="mt-0.5 shrink-0 text-success" /><span>{t(`about.${k}`)}</span>
              </div>
            ))}
            {LICENSE_DENY.map((k) => (
              <div key={k} className="flex gap-2 text-sm text-muted">
                <X size={16} className="mt-0.5 shrink-0 text-danger" /><span>{t(`about.${k}`)}</span>
              </div>
            ))}
          </div>
        </section>

        {/* 更多信息 */}
        <section>
          <div className="mb-1.5 text-sm font-semibold text-ink">{t("about.more")}</div>
          <div className="space-y-2 rounded-card border border-border p-4 text-sm">
            <a href="https://github.com/matrixplusio/mxcwpp" target="_blank" rel="noreferrer" className="flex items-center gap-2 text-primary hover:underline">
              <ExternalLink size={15} />github.com/matrixplusio/mxcwpp
            </a>
            <div className="flex items-center gap-2 text-muted"><Mail size={15} className="text-faint" />{t("about.commercialContact")}</div>
            <div className="flex items-center gap-2 text-muted"><User size={15} className="text-faint" />{t("about.maintainedBy", { brand: BRAND })}</div>
          </div>
        </section>

        <p className="text-center text-xs text-faint">{t("about.rights", { brand: BRAND })}</p>
      </div>
    </Modal>
  );
}

export function Header() {
  const { t, i18n } = useTranslation();
  const pathname = usePathname();
  const current = MENUS.find((m) => pathname.startsWith(m.path));
  const [aboutOpen, setAboutOpen] = useState(false);
  const mode = useThemeStore((s) => s.mode);
  const toggleTheme = useThemeStore((s) => s.toggle);
  const isEn = i18n.language === "en";

  return (
    <header className="flex h-16 shrink-0 items-center border-b border-border bg-surface px-6">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted">{t("nav.workspace")}</span>
        <span className="text-border">/</span>
        <span className="font-semibold text-ink">{t(`nav.${current?.key ?? "dashboard"}`)}</span>
      </div>
      <div className="ml-auto flex items-center gap-1">
        <button
          onClick={() => setLang(isEn ? "zh" : "en")}
          className="flex h-9 items-center gap-1 rounded-control px-2.5 text-sm font-medium text-muted transition-colors hover:bg-bg hover:text-ink"
          title={isEn ? "切换中文 / Switch to Chinese" : "Switch to English / 切换英文"}
        >
          <Languages size={18} />
          {isEn ? "EN" : "中"}
        </button>
        <button
          onClick={toggleTheme}
          className="flex h-9 w-9 items-center justify-center rounded-control text-muted transition-colors hover:bg-bg hover:text-ink"
          title={mode === "dark" ? t("header.switchLight") : t("header.switchDark")}
        >
          {mode === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button
          onClick={() => setAboutOpen(true)}
          className="flex h-9 w-9 items-center justify-center rounded-control text-muted transition-colors hover:bg-bg hover:text-ink"
          title={t("header.about")}
        >
          <Info size={18} />
        </button>
        <NotificationBell />
        <div className="mx-2 h-6 w-px bg-border" />
        <UserMenu />
      </div>
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} />
    </header>
  );
}
