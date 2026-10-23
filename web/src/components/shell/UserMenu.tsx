"use client";
import { useEffect, useRef, useState } from "react";
import { ChevronDown, KeyRound, LogOut, Moon, Sun } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useMutation } from "@tanstack/react-query";
import { useAuthStore } from "@/stores/auth";
import { useThemeStore } from "@/stores/theme";
import { authApi } from "@/lib/api/auth";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { toast } from "@/components/ui/toast";

export function UserMenu() {
  const { t } = useTranslation();
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const clear = useAuthStore((s) => s.clear);
  const mode = useThemeStore((s) => s.mode);
  const toggleTheme = useThemeStore((s) => s.toggle);
  const [open, setOpen] = useState(false);
  const [pwdOpen, setPwdOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  async function logout() {
    try { await authApi.logout(); } catch { /* ignore */ }
    clear();
    router.push("/login");
  }

  const changePwd = useMutation({
    mutationFn: () => authApi.changePassword(oldPwd, newPwd),
    onSuccess: () => {
      toast.success(t("header.pwdChanged"));
      setPwdOpen(false);
      logout();
    },
    onError: (e: Error) => setErr(e.message),
  });

  function submitPwd() {
    setErr("");
    if (newPwd.length < 6) { setErr(t("header.errMinLength")); return; }
    if (newPwd !== confirmPwd) { setErr(t("header.errMismatch")); return; }
    changePwd.mutate();
  }

  function openPwd() {
    setOpen(false);
    setOldPwd(""); setNewPwd(""); setConfirmPwd(""); setErr("");
    setPwdOpen(true);
  }

  const initial = user?.username?.[0]?.toUpperCase() ?? "U";
  const roleLabel = (role?: string) =>
    role === "admin" ? t("header.roleAdmin") : role === "user" ? t("header.roleUser") : role ?? "—";

  return (
    <>
      <div className="relative" ref={ref}>
        <button
          onClick={() => setOpen((v) => !v)}
          className="flex h-9 items-center gap-2 rounded-control pl-1 pr-2 text-sm text-ink transition-colors hover:bg-bg"
        >
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-primary to-accent text-xs font-semibold text-white">
            {initial}
          </div>
          <span className="font-medium">{user?.username ?? t("header.notLoggedIn")}</span>
          <ChevronDown size={14} className="text-muted" />
        </button>

        {open && (
          <div className="absolute right-0 top-11 z-50 w-56 overflow-hidden rounded-card border border-border bg-surface shadow-float">
            <div className="flex items-center gap-3 border-b border-border px-4 py-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-primary to-accent text-sm font-semibold text-white">
                {initial}
              </div>
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-ink">{user?.username ?? t("header.notLoggedIn")}</div>
                <div className="text-xs text-muted">{roleLabel(user?.role)}</div>
              </div>
            </div>
            <button onClick={toggleTheme} className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm text-ink transition-colors hover:bg-bg">
              {mode === "dark" ? <Sun size={16} className="text-muted" /> : <Moon size={16} className="text-muted" />}
              {mode === "dark" ? t("header.lightMode") : t("header.darkMode")}
            </button>
            <button onClick={openPwd} className="flex w-full items-center gap-2 border-t border-border px-4 py-2.5 text-left text-sm text-ink transition-colors hover:bg-bg">
              <KeyRound size={16} className="text-muted" />{t("header.changePassword")}
            </button>
            <button onClick={logout} className="flex w-full items-center gap-2 border-t border-border px-4 py-2.5 text-left text-sm text-danger transition-colors hover:bg-bg">
              <LogOut size={16} />{t("header.logout")}
            </button>
          </div>
        )}
      </div>

      <Modal
        open={pwdOpen}
        onClose={() => setPwdOpen(false)}
        title={t("header.changePassword")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPwdOpen(false)}>{t("common.cancel")}</Button>
            <Button onClick={submitPwd} disabled={changePwd.isPending || !oldPwd || !newPwd}>
              {changePwd.isPending ? t("common.submitting") : t("header.confirmChange")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("header.currentPassword")} required>
            <Input type="password" value={oldPwd} onChange={(e) => setOldPwd(e.target.value)} placeholder={t("header.currentPasswordPlaceholder")} />
          </FormField>
          <FormField label={t("header.newPassword")} required>
            <Input type="password" value={newPwd} onChange={(e) => setNewPwd(e.target.value)} placeholder={t("header.newPasswordPlaceholder")} />
          </FormField>
          <FormField label={t("header.confirmNewPassword")} required>
            <Input type="password" value={confirmPwd} onChange={(e) => setConfirmPwd(e.target.value)} placeholder={t("header.confirmNewPasswordPlaceholder")} />
          </FormField>
          {err && <p className="text-sm text-danger">{err}</p>}
        </div>
      </Modal>
    </>
  );
}
