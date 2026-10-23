"use client";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { AgentPolicy } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { toast } from "@/components/ui/toast";

type FleetSwitch = "auto_update" | "auto_plugin_broadcast";

/**
 * Agent 运行时策略。这里的每个开关都对全网主机同时生效：
 * 打开自动升级 / 插件自动广播之前必须二次确认——一次「设为最新」就是全网同时发版，没有灰度。
 */
export function AgentPolicyCard() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["sys-agent-policy"],
    queryFn: () => systemApi.getAgentPolicy(),
  });

  const [form, setForm] = useState<AgentPolicy | null>(null);
  const [pending, setPending] = useState<FleetSwitch | null>(null);
  useEffect(() => {
    if (data) setForm(data.policy);
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: (p: AgentPolicy) => systemApi.updateAgentPolicy(p),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-agent-policy"] });
      toast.success(t("system.agentPolicy.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const dirty =
    !!data &&
    !!form &&
    (form.identity_conflict !== data.policy.identity_conflict ||
      form.auto_update !== data.policy.auto_update ||
      form.auto_plugin_broadcast !== data.policy.auto_plugin_broadcast);

  // 打开全网开关先确认；关闭无需确认。
  const toggle = (key: FleetSwitch, next: boolean) => {
    if (next) setPending(key);
    else setForm((f) => (f ? { ...f, [key]: false } : f));
  };

  return (
    <Card>
      <CardHeader
        title={t("system.agentPolicy.title")}
        extra={
          <Button onClick={() => form && saveMutation.mutate(form)} disabled={saveMutation.isPending || !dirty}>
            {saveMutation.isPending ? t("common.saving") : t("common.save")}
          </Button>
        }
      />
      <div className="px-5 pb-5">
        <p className="text-sm text-muted">{t("system.agentPolicy.desc")}</p>
        {data && !data.configured && <p className="mt-2 text-xs text-warning">{t("system.agentPolicy.notConfigured")}</p>}
        {isLoading || !form ? (
          <p className="py-6 text-sm text-muted">{t("common.loading")}</p>
        ) : (
          <div className="mt-4 max-w-3xl divide-y divide-border">
            <section className="pb-5">
              <div className="mb-3 text-sm font-medium text-ink">{t("system.agentPolicy.identityConflict")}</div>
              <div className="grid gap-3 sm:grid-cols-2" role="radiogroup">
                {(["reject", "alert"] as const).map((mode) => {
                  const active = form.identity_conflict === mode;
                  return (
                    <label
                      key={mode}
                      className={`flex cursor-pointer gap-3 rounded-card border p-4 transition-colors ${
                        active ? "border-primary bg-primary/5" : "border-border hover:border-border-strong hover:bg-bg"
                      }`}
                    >
                      <input
                        type="radio"
                        name="identity_conflict"
                        className="mt-0.5 accent-primary"
                        checked={active}
                        onChange={() => setForm((f) => (f ? { ...f, identity_conflict: mode } : f))}
                      />
                      <span className="space-y-1">
                        <span className="block text-sm font-medium text-ink">{t(`system.agentPolicy.mode.${mode}`)}</span>
                        <span className="block text-xs leading-relaxed text-muted">{t(`system.agentPolicy.modeHint.${mode}`)}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </section>

            {(["auto_update", "auto_plugin_broadcast"] as const).map((key) => (
              <section key={key} className="flex items-center justify-between gap-8 py-5 last:pb-0">
                <div className="space-y-1">
                  <div className="text-sm font-medium text-ink">{t(`system.agentPolicy.${key}`)}</div>
                  <div className="text-xs leading-relaxed text-muted">{t(`system.agentPolicy.${key}Hint`)}</div>
                </div>
                <Switch checked={form[key]} onChange={(next) => toggle(key, next)} />
              </section>
            ))}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={!!pending}
        danger
        title={pending ? t(`system.agentPolicy.confirmTitle.${pending}`) : ""}
        desc={pending ? t(`system.agentPolicy.confirmDesc.${pending}`) : undefined}
        confirmText={t("system.agentPolicy.confirmEnable")}
        onConfirm={() => {
          if (pending) setForm((f) => (f ? { ...f, [pending]: true } : f));
          setPending(null);
        }}
        onCancel={() => setPending(null)}
      />
    </Card>
  );
}
