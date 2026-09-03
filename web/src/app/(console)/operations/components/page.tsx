"use client";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { operationsApi } from "@/lib/api/operations";
import type {
  Component,
  ComponentCategory,
  ComponentVersion,
  ComponentPackage,
  ComponentPushRecord,
} from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { Tabs } from "@/components/ui/Tabs";
import { StatusTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";
import { toast } from "@/components/ui/toast";

type CategoryTone = "info" | "success" | "neutral";
const buildCategoryMeta = (t: TFunction): Record<ComponentCategory, { label: string; tone: CategoryTone }> => ({
  agent: { label: "Agent", tone: "info" },
  plugin: { label: t("operations.components.catPlugin"), tone: "success" },
  dependency: { label: t("operations.components.catDependency"), tone: "neutral" },
});

const buildTabItems = (t: TFunction) => [
  { key: "all", label: t("operations.components.tabAll") },
  { key: "agent", label: "Agent" },
  { key: "plugin", label: t("operations.components.catPlugin") },
  { key: "dependency", label: t("operations.components.catDependency") },
];

const buildCategoryFormOptions = (t: TFunction) => [
  { label: t("operations.components.categoryAgentFull"), value: "agent" },
  { label: t("operations.components.catPlugin"), value: "plugin" },
  { label: t("operations.components.catDependency"), value: "dependency" },
];

const buildPushStatusMeta = (t: TFunction): Record<string, { label: string; tone: "success" | "danger" | "info" | "neutral" }> => ({
  success: { label: t("operations.components.pushSuccess"), tone: "success" },
  failed: { label: t("operations.components.pushFailed"), tone: "danger" },
  pushing: { label: t("operations.components.pushPushing"), tone: "info" },
  pending: { label: t("operations.components.pushPending"), tone: "info" },
  cancelled: { label: t("operations.components.pushCancelled"), tone: "neutral" },
});

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

interface ComponentForm {
  name: string;
  category: ComponentCategory;
  description: string;
}
const emptyComponentForm: ComponentForm = { name: "", category: "agent", description: "" };

interface VersionForm {
  version: string;
  changelog: string;
}
const emptyVersionForm: VersionForm = { version: "", changelog: "" };

export default function ComponentsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const categoryMeta = buildCategoryMeta(t);
  const tabItems = buildTabItems(t);
  const categoryFormOptions = buildCategoryFormOptions(t);
  const pushStatusMeta = buildPushStatusMeta(t);
  const [category, setCategory] = useState("all");
  const [keyword, setKeyword] = useState("");

  const { data: components, isLoading } = useQuery({
    queryKey: ["ops-components"],
    queryFn: () => operationsApi.listComponents(),
  });

  const rows = useMemo<Component[]>(() => {
    const list = components ?? [];
    const kw = keyword.trim().toLowerCase();
    return list.filter((c) => {
      if (category !== "all" && c.category !== category) return false;
      if (kw && !c.name.toLowerCase().includes(kw)) return false;
      return true;
    });
  }, [components, category, keyword]);

  // ---- create component ----
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<ComponentForm>(emptyComponentForm);

  const createMutation = useMutation({
    mutationFn: () =>
      operationsApi.createComponent({
        name: createForm.name,
        category: createForm.category,
        description: createForm.description || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-components"] });
      setCreateOpen(false);
      toast.success(t("operations.components.created"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- delete component ----
  const [deleting, setDeleting] = useState<Component | null>(null);
  const deleteMutation = useMutation({
    mutationFn: (id: number) => operationsApi.deleteComponent(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-components"] });
      setDeleting(null);
      toast.success(t("operations.components.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- broadcast plugin configs (no-body POST) ----
  const [broadcastOpen, setBroadcastOpen] = useState(false);
  const broadcastMutation = useMutation({
    mutationFn: () => operationsApi.broadcastPlugins(),
    onSuccess: () => {
      setBroadcastOpen(false);
      toast.success(t("operations.components.broadcasted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- detail drawer ----
  const [detail, setDetail] = useState<Component | null>(null);
  const detailQuery = useQuery({
    queryKey: ["ops-versions", detail?.id],
    queryFn: () => operationsApi.listVersions(detail!.id),
    enabled: !!detail,
  });

  // ---- release version ----
  const [releaseOpen, setReleaseOpen] = useState(false);
  const [versionForm, setVersionForm] = useState<VersionForm>(emptyVersionForm);
  const releaseMutation = useMutation({
    mutationFn: () =>
      operationsApi.createVersion(detail!.id, {
        version: versionForm.version,
        changelog: versionForm.changelog || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-versions", detail?.id] });
      queryClient.invalidateQueries({ queryKey: ["ops-components"] });
      setReleaseOpen(false);
      toast.success(t("operations.components.released"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- set latest ----
  const setLatestMutation = useMutation({
    mutationFn: (versionId: number) => operationsApi.setLatest(detail!.id, versionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-versions", detail?.id] });
      queryClient.invalidateQueries({ queryKey: ["ops-components"] });
      toast.success(t("operations.components.setLatestDone"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- delete version ----
  const [deletingVersion, setDeletingVersion] = useState<ComponentVersion | null>(null);
  const deleteVersionMutation = useMutation({
    mutationFn: (versionId: number) => operationsApi.deleteVersion(detail!.id, versionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-versions", detail?.id] });
      queryClient.invalidateQueries({ queryKey: ["ops-components"] });
      setDeletingVersion(null);
      toast.success(t("operations.components.versionDeleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- push records drawer ----
  const [recordsOpen, setRecordsOpen] = useState(false);
  const [recordPage, setRecordPage] = useState(1);
  const recordsQuery = useQuery({
    queryKey: ["ops-push-records", recordPage],
    queryFn: () => operationsApi.listPushRecords({ page: recordPage, page_size: 10 }),
    enabled: recordsOpen,
  });

  const columns: Column<Component>[] = [
    {
      key: "category",
      title: t("operations.components.colCategory"),
      render: (r) => {
        const meta = categoryMeta[r.category];
        return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
      },
    },
    { key: "name", title: t("operations.components.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "latest_version",
      title: t("operations.components.colLatestVersion"),
      render: (r) =>
        r.latest_version ? (
          <span className="font-mono text-ink">{r.latest_version}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      key: "version_count",
      title: t("operations.components.colVersionCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.version_count ?? 0}</span>,
    },
    {
      key: "package_count",
      title: t("operations.components.colPackageCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.package_count ?? 0}</span>,
    },
    { key: "created_by", title: t("operations.components.colCreatedBy"), render: (r) => <span className="text-faint">{r.created_by || "—"}</span> },
    {
      key: "created_at",
      title: t("operations.components.colCreatedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-3">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              setDetail(r);
            }}
          >
            {t("common.details")}
          </button>
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={(e) => {
              e.stopPropagation();
              setDeleting(r);
            }}
          >
            {t("common.delete")}
          </button>
        </div>
      ),
    },
  ];

  const recordColumns: Column<ComponentPushRecord>[] = [
    {
      key: "component_name",
      title: t("operations.components.colComponent"),
      render: (r) => <span className="font-medium text-ink">{r.component_name}</span>,
    },
    { key: "version", title: t("common.version"), render: (r) => <span className="font-mono text-ink">{r.version || "—"}</span> },
    { key: "target_type", title: t("operations.components.colTarget"), render: (r) => <span className="text-muted">{r.target_type}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const meta = pushStatusMeta[r.status] ?? { label: r.status, tone: "neutral" as const };
        return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
      },
    },
    {
      key: "progress",
      title: t("operations.components.colProgress"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.progress ?? 0}%</span>,
    },
    {
      key: "success_count",
      title: t("operations.components.colSuccessFailed"),
      align: "right",
      render: (r) => (
        <span className="tabular-nums">
          <span className="text-success">{r.success_count ?? 0}</span>
          {" / "}
          <span className="text-danger">{r.failed_count ?? 0}</span>
        </span>
      ),
    },
    {
      key: "created_at",
      title: t("common.time"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
  ];

  const detailData = detailQuery.data;

  return (
    <>
      <div className="space-y-4">
        <Tabs items={tabItems} active={category} onChange={setCategory} />
        <FilterBar
          extra={
            <div className="flex gap-2">
              <Button variant="ghost" onClick={() => setBroadcastOpen(true)}>
                {t("operations.components.pushPluginConfig")}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setRecordPage(1);
                  setRecordsOpen(true);
                }}
              >
                {t("operations.components.pushRecords")}
              </Button>
              <Button
                onClick={() => {
                  setCreateForm(emptyComponentForm);
                  setCreateOpen(true);
                }}
              >
                {t("operations.components.create")}
              </Button>
            </div>
          }
        >
          <SearchInput value={keyword} onChange={setKeyword} placeholder={t("operations.components.searchPlaceholder")} />
        </FilterBar>
        <Card>
          <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} loading={isLoading} emptyText={t("operations.components.empty")} />
        </Card>
      </div>

      {/* 新建组件 */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("operations.components.createTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
              {createMutation.isPending ? t("operations.components.creating") : t("operations.components.createBtn")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("operations.components.fieldCategory")}>
            <Select
              value={createForm.category}
              onChange={(v) => setCreateForm((f) => ({ ...f, category: v as ComponentCategory }))}
              options={categoryFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("operations.components.fieldName")} required>
            <Input value={createForm.name} onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("operations.components.fieldDescription")}>
            <Textarea
              value={createForm.description}
              onChange={(e) => setCreateForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
        </div>
      </Modal>

      {/* 详情 Drawer */}
      <Drawer open={!!detail} onClose={() => setDetail(null)} title={detail ? t("operations.components.detailTitleNamed", { name: detail.name }) : t("operations.components.detailTitle")} width={640}>
        {detail && (
          <div className="space-y-5">
            <div className="rounded-card border border-border bg-surface-muted/50 p-4">
              <div className="flex items-center gap-2">
                <StatusTag tone={categoryMeta[detail.category].tone}>{categoryMeta[detail.category].label}</StatusTag>
                <span className="font-semibold text-ink">{detail.name}</span>
              </div>
              {detail.description && <p className="mt-2 text-sm text-muted">{detail.description}</p>}
            </div>

            <div className="flex items-center justify-between">
              <h4 className="text-[13px] font-semibold text-muted">{t("operations.components.versionList")}</h4>
              <Button
                variant="ghost"
                onClick={() => {
                  setVersionForm(emptyVersionForm);
                  setReleaseOpen(true);
                }}
              >
                {t("operations.components.releaseVersion")}
              </Button>
            </div>

            {detailQuery.isLoading && <div className="text-sm text-muted">{t("common.loading")}</div>}
            {detailQuery.isError && <div className="text-sm text-danger">{t("operations.components.loadError")}</div>}
            {detailData && detailData.versions.length === 0 && <EmptyState title={t("operations.components.emptyVersions")} desc="" />}

            <div className="space-y-3">
              {detailData?.versions.map((v) => (
                <VersionCard
                  key={v.id}
                  version={v}
                  onSetLatest={() => setLatestMutation.mutate(v.id)}
                  onDelete={() => setDeletingVersion(v)}
                  setLatestPending={setLatestMutation.isPending}
                  t={t}
                />
              ))}
            </div>
          </div>
        )}
      </Drawer>

      {/* 发布版本 */}
      <Modal
        open={releaseOpen}
        onClose={() => setReleaseOpen(false)}
        title={t("operations.components.releaseTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setReleaseOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => releaseMutation.mutate()} disabled={releaseMutation.isPending}>
              {releaseMutation.isPending ? t("operations.components.releasing") : t("operations.components.releaseBtn")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("operations.components.fieldVersion")} required>
            <Input
              value={versionForm.version}
              onChange={(e) => setVersionForm((f) => ({ ...f, version: e.target.value }))}
              placeholder={t("operations.components.versionPlaceholder")}
            />
          </FormField>
          <FormField label={t("operations.components.fieldChangelog")}>
            <Textarea
              value={versionForm.changelog}
              onChange={(e) => setVersionForm((f) => ({ ...f, changelog: e.target.value }))}
            />
          </FormField>
          <p className="text-xs text-faint">{t("operations.components.uploadHint")}</p>
        </div>
      </Modal>

      {/* 推送记录 Drawer */}
      <Drawer open={recordsOpen} onClose={() => setRecordsOpen(false)} title={t("operations.components.pushRecordsTitle")} width={720}>
        <DataTable
          columns={recordColumns}
          rows={recordsQuery.data?.items ?? []}
          rowKey={(r) => r.id}
          loading={recordsQuery.isLoading}
          emptyText={t("operations.components.emptyPushRecords")}
        />
        <Pagination
          page={recordPage}
          pageSize={10}
          total={recordsQuery.data?.total ?? 0}
          onChange={setRecordPage}
        />
      </Drawer>

      {/* 删除组件 */}
      <ConfirmDialog
        open={!!deleting}
        title={t("operations.components.deleteTitle")}
        desc={deleting ? t("operations.components.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />

      {/* 删除版本 */}
      <ConfirmDialog
        open={!!deletingVersion}
        title={t("operations.components.deleteVersionTitle")}
        desc={deletingVersion ? t("operations.components.deleteVersionConfirmDesc", { version: deletingVersion.version }) : undefined}
        loading={deleteVersionMutation.isPending}
        onConfirm={() => deletingVersion && deleteVersionMutation.mutate(deletingVersion.id)}
        onCancel={() => setDeletingVersion(null)}
      />

      {/* 广播插件配置确认 */}
      <ConfirmDialog
        open={broadcastOpen}
        title={t("operations.components.pushPluginConfig")}
        desc={t("operations.components.broadcastDesc")}
        danger={false}
        confirmText={t("operations.components.broadcastConfirm")}
        loading={broadcastMutation.isPending}
        onConfirm={() => broadcastMutation.mutate()}
        onCancel={() => setBroadcastOpen(false)}
      />
    </>
  );
}

function VersionCard({
  version,
  onSetLatest,
  onDelete,
  setLatestPending,
  t,
}: {
  version: ComponentVersion;
  onSetLatest: () => void;
  onDelete: () => void;
  setLatestPending: boolean;
  t: TFunction;
}) {
  return (
    <div className="rounded-card border border-border p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono font-semibold text-ink">{version.version}</span>
          {version.is_latest && <StatusTag tone="success">{t("operations.components.latest")}</StatusTag>}
        </div>
        <div className="flex items-center gap-3">
          {!version.is_latest && (
            <button
              type="button"
              className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
              onClick={onSetLatest}
              disabled={setLatestPending}
            >
              {t("operations.components.setLatest")}
            </button>
          )}
          <button type="button" className="text-sm text-danger transition-colors hover:opacity-80" onClick={onDelete}>
            {t("operations.components.deleteVersion")}
          </button>
        </div>
      </div>
      {version.changelog && <p className="mt-2 text-sm text-muted">{version.changelog}</p>}
      <p className="mt-1 text-xs text-faint tabular-nums">{version.created_at}</p>

      {version.packages && version.packages.length > 0 ? (
        <table className="mt-3 w-full text-xs">
          <thead>
            <tr className="text-[11px] uppercase tracking-wide text-faint">
              <th className="py-1 text-left font-semibold">{t("operations.components.pkgOs")}</th>
              <th className="py-1 text-left font-semibold">{t("operations.components.pkgArch")}</th>
              <th className="py-1 text-left font-semibold">{t("operations.components.pkgType")}</th>
              <th className="py-1 text-left font-semibold">{t("operations.components.pkgFile")}</th>
              <th className="py-1 text-right font-semibold">{t("operations.components.pkgSize")}</th>
              <th className="py-1 text-right font-semibold">{t("operations.components.pkgStatus")}</th>
            </tr>
          </thead>
          <tbody>
            {version.packages.map((p: ComponentPackage) => (
              <tr key={p.id} className="border-t border-border">
                <td className="py-1.5 text-muted">{p.os || "—"}</td>
                <td className="py-1.5 text-muted">{p.arch}</td>
                <td className="py-1.5 text-muted">{p.pkg_type}</td>
                <td className="py-1.5 text-muted">{p.file_name || "—"}</td>
                <td className="py-1.5 text-right tabular-nums text-muted">{formatBytes(p.file_size)}</td>
                <td className="py-1.5 text-right">
                  <StatusTag tone={p.enabled ? "success" : "neutral"}>{p.enabled ? t("common.enabled") : t("common.disabled")}</StatusTag>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="mt-3 text-xs text-faint">{t("operations.components.emptyPackages")}</p>
      )}
    </div>
  );
}
