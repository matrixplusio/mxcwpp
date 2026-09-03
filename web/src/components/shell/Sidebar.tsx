"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { MENUS } from "@/config/menu";
import { cn } from "@/lib/utils/cn";
import { useSiteStore } from "@/stores/site-config";
import { useAuthStore } from "@/stores/auth";
import { BRAND } from "@/lib/brand";

export function Sidebar() {
  const { t } = useTranslation();
  const pathname = usePathname();
  const siteName = useSiteStore((s) => s.siteName);
  const logo = useSiteStore((s) => s.logo);
  const perms = useAuthStore((s) => s.user?.permissions);

  // 按当前用户权限过滤菜单：用户拥有该模块任一 view 权限即显示。
  // 权限码为 "module:action"；菜单声明的 perms 为模块码，命中其 ":view" 即可见。
  // perms 未知（旧会话/未登录态）时全显示，避免空菜单。
  const menus = MENUS.filter((m) => !perms || m.perms.length === 0 || m.perms.some((mod) => perms.includes(`${mod}:view`)));

  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-surface">
      <div className="flex h-16 shrink-0 items-center gap-2.5 px-5">
        <img src={logo || "/logo.png"} alt="logo" className="h-9 w-9 shrink-0 object-contain" />
        <span className="truncate font-extrabold tracking-tight text-ink">{siteName}</span>
      </div>
      <div className="px-5 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-faint">{t("nav.section")}</div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
        {menus.map((m) => {
          const active = m.path === "/dashboard" ? pathname === m.path : pathname.startsWith(m.path);
          const Icon = m.icon;
          return (
            <Link
              key={m.key}
              href={m.path}
              className={cn(
                "flex h-10 items-center gap-3 rounded-control px-3 text-sm transition-all duration-150",
                active
                  ? "bg-primary font-medium text-white shadow-sm shadow-primary/25"
                  : "text-muted hover:bg-bg hover:text-ink",
              )}
            >
              <Icon size={18} className={active ? "text-white" : "text-faint"} />
              {t(`nav.${m.key}`)}
            </Link>
          );
        })}
      </nav>
      <div className="shrink-0 border-t border-border px-5 py-3 text-[11px] text-faint">
        {t("common.poweredBy", { brand: BRAND })}
      </div>
    </aside>
  );
}
