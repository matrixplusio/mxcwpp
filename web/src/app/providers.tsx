"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { I18nextProvider } from "react-i18next";
import i18n from "@/lib/i18n"; // 副作用初始化 i18next(应用全局生效)
import { Toaster } from "@/components/ui/Toaster";
import { useThemeStore } from "@/stores/theme";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } }));
  const mode = useThemeStore((s) => s.mode);
  const init = useThemeStore((s) => s.init);

  // 首次挂载读取本地存储并应用主题
  useEffect(() => { init(); }, [init]);
  // 主题变化时同步 <html>.dark 类
  useEffect(() => {
    document.documentElement.classList.toggle("dark", mode === "dark");
  }, [mode]);
  return (
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        {children}
        <Toaster />
      </QueryClientProvider>
    </I18nextProvider>
  );
}
