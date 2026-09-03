"use client";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { SiteConfig } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { toast } from "@/components/ui/toast";

const emptyForm: SiteConfig = { site_name: "", site_logo: "", site_domain: "", backend_url: "" };

export default function SettingsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["sys-site-config"],
    queryFn: () => systemApi.getSiteConfig(),
  });

  const [form, setForm] = useState<SiteConfig>(emptyForm);
  useEffect(() => {
    if (data) setForm({ site_name: data.site_name, site_logo: data.site_logo, site_domain: data.site_domain, backend_url: data.backend_url });
  }, [data]);

  const dirty = !!data && (
    form.site_name !== data.site_name ||
    form.site_logo !== data.site_logo ||
    form.site_domain !== data.site_domain ||
    form.backend_url !== data.backend_url
  );

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateSiteConfig(form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-site-config"] });
      queryClient.invalidateQueries({ queryKey: ["site-config"] });
      toast.success(t("system.settings.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const fileRef = useRef<HTMLInputElement>(null);
  const uploadMutation = useMutation({
    mutationFn: (file: File) => systemApi.uploadLogo(file),
    onSuccess: (res) => {
      setForm((f) => ({ ...f, site_logo: res.logo_url }));
      queryClient.invalidateQueries({ queryKey: ["sys-site-config"] });
      queryClient.invalidateQueries({ queryKey: ["site-config"] });
      toast.success(t("system.settings.logoUploaded"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const onPickFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadMutation.mutate(file);
    e.target.value = "";
  };

  return (
    <Card>
      <CardHeader
        title={t("system.settings.title")}
        extra={
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending || !dirty}>
            {saveMutation.isPending ? t("common.saving") : t("common.save")}
          </Button>
        }
      />
      <div className="px-5 pb-5">
        {isLoading ? (
          <p className="py-6 text-sm text-muted">{t("common.loading")}</p>
        ) : (
          <div className="max-w-xl space-y-4">
            <FormField label={t("system.settings.fieldSiteName")} required>
              <Input value={form.site_name} onChange={(e) => setForm((f) => ({ ...f, site_name: e.target.value }))} />
            </FormField>
            <FormField label={t("system.settings.fieldSiteLogo")}>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  {form.site_logo ? (
                    <img
                      src={form.site_logo}
                      alt={t("system.settings.logoAlt")}
                      className="h-12 w-12 rounded-card object-contain border border-border"
                    />
                  ) : (
                    <div className="flex h-12 w-12 items-center justify-center rounded-card border border-border bg-bg text-xs text-muted">
                      {t("system.settings.logoNone")}
                    </div>
                  )}
                  <Button
                    variant="ghost"
                    onClick={() => fileRef.current?.click()}
                    disabled={uploadMutation.isPending}
                  >
                    {uploadMutation.isPending ? t("system.settings.uploading") : t("system.settings.uploadLogo")}
                  </Button>
                  <input
                    ref={fileRef}
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={onPickFile}
                  />
                </div>
                <Input
                  value={form.site_logo}
                  onChange={(e) => setForm((f) => ({ ...f, site_logo: e.target.value }))}
                  placeholder={t("system.settings.logoUrlPlaceholder")}
                />
              </div>
            </FormField>
            <FormField label={t("system.settings.fieldSiteDomain")}>
              <Input value={form.site_domain} onChange={(e) => setForm((f) => ({ ...f, site_domain: e.target.value }))} />
            </FormField>
            <FormField label={t("system.settings.fieldBackendUrl")}>
              <Input value={form.backend_url} onChange={(e) => setForm((f) => ({ ...f, backend_url: e.target.value }))} />
            </FormField>
          </div>
        )}
      </div>
    </Card>
  );
}
