"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { alertsApi, whitelistApi } from "@/lib/api/alerts";
import type { Alert, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { CopyButton } from "@/components/ui/CopyButton";
import { toast } from "@/components/ui/toast";

const isSeverity = (v: string): v is Severity => ["critical", "high", "medium", "low"].includes(v);

// 分类 → 攻击阶段含义 + 处置建议(研判依据)
const CATEGORY_META: Record<string, { name: string; meaning: string; action: string }> = {
  attack_chain: { name: "多步攻击链", meaning: "多个步骤按 kill-chain 顺序串联命中,高置信攻击。", action: "立即隔离主机,溯源完整链路,封禁外联。" },
  initial_access: { name: "初始访问", meaning: "疑似通过 Web/服务入口获得立足点。", action: "排查入口利用与 Webshell,检查可疑上传。" },
  execution: { name: "执行", meaning: "执行了可疑进程/命令。", action: "核对命令行与父进程血缘是否合法。" },
  webshell: { name: "Webshell", meaning: "检测到 Web 后门特征。", action: "定位清除 Webshell,审计 Web 目录写入。" },
  reverse_shell: { name: "反弹Shell", meaning: "进程对外建立交互式 shell。", action: "立即隔离,阻断外联,溯源来源。" },
  persistence: { name: "持久化", meaning: "向 cron/systemd/authorized_keys 等位置写入,意图常驻。", action: "检查并清除持久化项。" },
  privilege_escalation: { name: "权限提升", meaning: "疑似提权(sudo/setuid/内核漏洞)。", action: "核查提权痕迹,修补漏洞。" },
  defense_evasion: { name: "防御规避", meaning: "rootkit/日志篡改/无文件执行等规避行为。", action: "做完整性校验,排查规避手法。" },
  credential_access: { name: "凭证访问", meaning: "读取 shadow/ssh key/云凭证等敏感凭证。", action: "立即轮换受影响凭证,排查泄露范围。" },
  discovery: { name: "发现/侦察", meaning: "短时探测系统/网络信息。", action: "确认是否合法运维。" },
  lateral_movement: { name: "横向移动", meaning: "向内网其他主机移动。", action: "隔离主机,核查横移凭证。" },
  network_scan: { name: "网络扫描", meaning: "对端口/主机批量扫描。", action: "封禁扫描源,核查暴露面。" },
  collection: { name: "数据收集", meaning: "访问/打包敏感数据。", action: "排查数据访问范围。" },
  command_and_control: { name: "命令与控制", meaning: "疑似 C2 外联/信标。", action: "封禁外联 IP/域名,隔离主机。" },
  c2_communication: { name: "命令与控制", meaning: "疑似 C2 外联/信标。", action: "封禁外联 IP/域名,隔离主机。" },
  exfiltration: { name: "数据渗出", meaning: "向外传输数据。", action: "阻断外传,评估泄露。" },
  cryptomining: { name: "挖矿", meaning: "启动挖矿程序/连接矿池。", action: "终止进程,清持久化,查入口。" },
  ransomware: { name: "勒索", meaning: "短时大量文件加密/改名。", action: "立即隔离,停止加密,启动备份恢复。" },
  impact: { name: "影响/破坏", meaning: "破坏性行为。", action: "隔离,评估业务影响,应急恢复。" },
  ioc_hit: { name: "威胁情报命中", meaning: "命中已知恶意 IOC。", action: "核查命中上下文,封禁指标。" },
};
const catMeta = (c: string) => CATEGORY_META[c] ?? { name: c || "未分类", meaning: "检测到可疑行为。", action: "核查该主机近期行为是否合法。" };

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-ink">{value}</span>
    </div>
  );
}

export default function ThreatAlertsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    severity: "",
    status: "",
    host_id: "",
    onlyChain: "",
  });

  const statusOptions = [
    { label: t("detection.threatAlerts.allStatus"), value: "" },
    { label: t("detection.threatAlerts.statusActive"), value: "active" },
    { label: t("detection.threatAlerts.statusResolved"), value: "resolved" },
    { label: t("detection.threatAlerts.statusIgnored"), value: "ignored" },
  ];
  const severityOptions = [
    { label: t("detection.threatAlerts.allSeverity"), value: "" },
    { label: t("common.severity.critical"), value: "critical" },
    { label: t("common.severity.high"), value: "high" },
    { label: t("common.severity.medium"), value: "medium" },
    { label: t("common.severity.low"), value: "low" },
  ];
  const kindOptions = [
    { label: t("detection.threatAlerts.allKind"), value: "" },
    { label: t("detection.threatAlerts.onlyChain"), value: "1" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["threat-alerts", params],
    queryFn: () =>
      alertsApi.list({
        page: params.page,
        page_size: params.page_size,
        alert_type: "detection", // 仅 EDR/检测来源
        severity: params.severity || undefined,
        status: params.status || undefined,
        host_id: params.host_id || undefined,
        category: params.onlyChain === "1" ? "attack_chain" : undefined,
      }),
  });

  const queryClient = useQueryClient();
  const [detail, setDetail] = useState<Alert | null>(null);
  const [markingFp, setMarkingFp] = useState<Alert | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["threat-alerts"] });

  // 用户研判:确认真实威胁 → 标记已处置
  const confirmRealMutation = useMutation({
    mutationFn: (a: Alert) => alertsApi.resolve(a.id, "用户研判:真实威胁,已确认"),
    onSuccess: () => {
      invalidate();
      setDetail(null);
      toast.success(t("detection.threatAlerts.confirmedReal"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // 用户研判:误报 → 解决告警 + 加白名单(学习:同规则+主机不再告警)
  const markFpMutation = useMutation({
    mutationFn: async (a: Alert) => {
      await whitelistApi.create({
        name: `误报-${a.rule_id}-${(a.host?.hostname || a.host_id).slice(0, 16)}`,
        rule_id: a.rule_id,
        host_id: a.host_id,
        category: a.category,
        severity: a.severity,
        reason: "用户研判:误报,自动加入白名单",
      });
      await alertsApi.resolve(a.id, "用户研判:误报");
    },
    onSuccess: () => {
      invalidate();
      setMarkingFp(null);
      setDetail(null);
      toast.success(t("detection.threatAlerts.markedFpLearned"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Alert>[] = [
    { key: "last_seen_at", title: t("detection.threatAlerts.colTime"), render: (r) => <span className="text-faint tabular-nums">{r.last_seen_at}</span> },
    {
      key: "title",
      title: t("detection.threatAlerts.colTitle"),
      render: (r) => (
        <div className="flex items-center gap-2">
          {r.category === "attack_chain" && <StatusTag tone="danger">{t("detection.threatAlerts.chainTag")}</StatusTag>}
          <span className="font-medium text-ink">{r.title}</span>
        </div>
      ),
    },
    { key: "severity", title: t("common.level"), render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : "—") },
    { key: "category", title: t("detection.threatAlerts.colCategory"), render: (r) => <span className="font-mono text-xs text-faint">{r.category || "—"}</span> },
    {
      key: "host",
      title: t("detection.threatAlerts.colHost"),
      render: (r) => (
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            className="font-medium text-ink transition-colors hover:text-primary"
            onClick={(e) => { e.stopPropagation(); setParams((p) => ({ ...p, host_id: r.host_id, page: 1 })); }}
          >
            {r.host?.hostname || r.host_id}
          </button>
          <CopyButton text={r.host_id} />
        </div>
      ),
    },
    { key: "hit_count", title: t("detection.threatAlerts.colHitCount"), align: "right", render: (r) => <span className="tabular-nums text-muted">{r.hit_count}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => (
        <StatusTag tone={r.status === "active" ? "danger" : r.status === "resolved" ? "success" : "neutral"}>
          {t(`detection.threatAlerts.status${r.status === "active" ? "Active" : r.status === "resolved" ? "Resolved" : "Ignored"}`)}
        </StatusTag>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <p className="text-sm text-muted">{t("detection.threatAlerts.intro")}</p>
        <FilterBar>
          <Select value={params.onlyChain} onChange={(v) => setParams((p) => ({ ...p, onlyChain: v, page: 1 }))} options={kindOptions} />
          <Select value={params.severity} onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))} options={severityOptions} />
          <Select value={params.status} onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))} options={statusOptions} />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("detection.threatAlerts.filterHostId")}
            className="w-56"
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("detection.threatAlerts.empty")}
            onRowClick={setDetail}
          />
          <Pagination page={params.page} pageSize={params.page_size} total={data?.total ?? 0} onChange={(page) => setParams((p) => ({ ...p, page }))} />
        </Card>
      </div>

      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        title={t("detection.threatAlerts.detailTitle")}
        width={560}
        footer={
          detail?.status === "active" ? (
            <>
              <Button variant="ghost" onClick={() => detail && setMarkingFp(detail)}>
                {t("detection.threatAlerts.markFp")}
              </Button>
              <Button onClick={() => detail && confirmRealMutation.mutate(detail)} disabled={confirmRealMutation.isPending}>
                {t("detection.threatAlerts.confirmReal")}
              </Button>
            </>
          ) : undefined
        }
      >
        {detail && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              {detail.category === "attack_chain" && <StatusTag tone="danger">{t("detection.threatAlerts.chainTag")}</StatusTag>}
              {isSeverity(detail.severity) && <SeverityTag level={detail.severity} />}
            </div>

            {/* 研判结论(这是什么 / 为什么是威胁 / 怎么处置) */}
            {(() => {
              const m = catMeta(detail.category);
              const why = detail.description && detail.description.length > 0 ? detail.description : m.meaning;
              return (
                <div className="rounded-md border border-line bg-surface-muted p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                    <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">AI</span>
                    {t("detection.threatAlerts.verdict")}
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-ink">
                    {detail.host?.hostname || detail.host_id} 上检测到{m.name}:{detail.title}。{why}
                  </p>
                  <div className="mt-3 text-sm font-semibold text-ink">{t("detection.threatAlerts.recommendation")}</div>
                  <p className="mt-1 text-sm leading-relaxed text-muted">{m.action}</p>
                </div>
              );
            })()}

            <div className="space-y-2">
            <Field label={t("detection.threatAlerts.colTitle")} value={detail.title} />
            <Field label={t("detection.threatAlerts.colCategory")} value={detail.category || "—"} />
            <Field label={t("detection.threatAlerts.colHost")} value={<span className="inline-flex items-center gap-1.5">{detail.host?.hostname || detail.host_id}<CopyButton text={detail.host_id} /></span>} />
            <Field label="host_id" value={<span className="inline-flex items-center gap-1.5 font-mono text-xs">{detail.host_id}<CopyButton text={detail.host_id} /></span>} />
            <Field label={t("detection.threatAlerts.colHitCount")} value={detail.hit_count} />
            <Field label={t("detection.threatAlerts.firstSeen")} value={<span className="tabular-nums">{detail.first_seen_at}</span>} />
            <Field label={t("detection.threatAlerts.lastSeen")} value={<span className="tabular-nums">{detail.last_seen_at}</span>} />
            {detail.description && <Field label={t("detection.threatAlerts.desc")} value={detail.description} />}
            {detail.actual && (
              <div>
                <div className="mb-1.5 mt-2 text-sm font-medium text-ink">{t("detection.threatAlerts.matched")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">{detail.actual}</pre>
              </div>
            )}
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!markingFp}
        title={t("detection.threatAlerts.markFpTitle")}
        desc={markingFp ? t("detection.threatAlerts.markFpDesc", { title: markingFp.title }) : undefined}
        loading={markFpMutation.isPending}
        onConfirm={() => markingFp && markFpMutation.mutate(markingFp)}
        onCancel={() => setMarkingFp(null)}
      />
    </>
  );
}
