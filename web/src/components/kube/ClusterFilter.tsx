"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { kubeApi } from "@/lib/api/kube";
import { Select } from "@/components/ui/Select";

/**
 * 集群筛选下拉。多集群场景下供安全告警/事件/基线等列表页按集群过滤。
 * 集群列表共用同一 queryKey 缓存，避免各页重复请求。
 */
export function ClusterFilter({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  const { data } = useQuery({
    queryKey: ["kube-clusters-options"],
    queryFn: () => kubeApi.listClusters({ page: 1, page_size: 200 }),
    staleTime: 60_000,
  });
  const options = [
    { label: t("kube.common.allClusters"), value: "" },
    ...(data?.items ?? []).map((c) => ({ label: c.name, value: String(c.id) })),
  ];
  return <Select value={value} onChange={onChange} options={options} />;
}
