"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Sidebar } from "@/components/shell/Sidebar";
import { Header } from "@/components/shell/Header";
import { useAuthStore } from "@/stores/auth";
import { useSiteStore } from "@/stores/site-config";
import { systemApi } from "@/lib/api/system";

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const hydrate = useAuthStore((s) => s.hydrate);
  const setSite = useSiteStore((s) => s.set);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    hydrate();
    const ok = useAuthStore.getState().isAuthenticated();
    if (!ok) { router.replace("/login"); return; }
    setReady(true);
  }, [hydrate, router]);

  const { data: siteCfg } = useQuery({
    queryKey: ["site-config"],
    queryFn: () => systemApi.getSiteConfig(),
    enabled: ready,
  });
  useEffect(() => {
    if (!siteCfg) return;
    setSite({ siteName: siteCfg.site_name || "MXCWPP", logo: siteCfg.site_logo || null });
    if (siteCfg.site_name && typeof document !== "undefined") document.title = siteCfg.site_name;
  }, [siteCfg, setSite]);

  if (!ready) return null;
  return (
    <div className="h-screen p-3 lg:p-4">
      <div className="h-full flex rounded-panel bg-surface border border-border shadow-card overflow-hidden">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <Header />
          <main className="flex-1 overflow-y-auto bg-surface-muted/50">
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              className="p-6 lg:p-8"
            >
              {children}
            </motion.div>
          </main>
        </div>
      </div>
    </div>
  );
}
