"use client";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Copy } from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Tabs } from "@/components/ui/Tabs";
import { toast } from "@/components/ui/toast";

const buildPkgTabs = (t: TFunction) => [
  { key: "rpm", label: t("operations.install.tabRpm") },
  { key: "deb", label: t("operations.install.tabDeb") },
];

const SUPPORTED_OS = [
  { badge: "CentOS", text: "CentOS 7/8/9" },
  { badge: "RHEL", text: "Red Hat 7/8/9" },
  { badge: "Rocky", text: "Rocky Linux 8/9" },
  { badge: "Debian", text: "Debian 10/11/12" },
  { badge: "Ubuntu", text: "Ubuntu 18.04/20.04/22.04" },
];

function CommandBlock({ command, t }: { command: string; t: TFunction }) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      toast.success(t("operations.install.copied"));
    } catch {
      toast.error(t("operations.install.copyFailed"));
    }
  };
  return (
    <div className="flex items-start gap-2">
      <pre className="flex-1 overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink">
        {command}
      </pre>
      <button
        type="button"
        onClick={copy}
        className="flex h-9 shrink-0 items-center gap-1.5 rounded-control border border-border px-3 text-sm text-muted transition-colors hover:text-ink"
      >
        <Copy size={14} />
        {t("operations.install.copy")}
      </button>
    </div>
  );
}

export default function InstallPage() {
  const { t } = useTranslation();
  const PKG_TABS = buildPkgTabs(t);
  const [httpAddr, setHttpAddr] = useState("");
  const [grpcAddr, setGrpcAddr] = useState("");
  const [pkgType, setPkgType] = useState("rpm");
  const [curlBase, setCurlBase] = useState("YOUR_SERVER");
  const [isLocalhost, setIsLocalhost] = useState(false);

  // 镜像 Vue：从当前访问地址推导服务器地址默认值
  useEffect(() => {
    const host = window.location.hostname;
    const local = host === "localhost" || host === "127.0.0.1" || host === "::1";
    setIsLocalhost(local);
    if (!local) {
      setHttpAddr(`${host}:8080`);
      setGrpcAddr(`${host}:6751`);
    }
    const port = window.location.port;
    setCurlBase(port && port !== "80" && port !== "443" ? `${host}:${port}` : host);
  }, []);

  const httpVal = httpAddr || "YOUR_HTTP_SERVER:8080";
  const grpcVal = grpcAddr || "YOUR_GRPC_SERVER:6751";

  const autoInstall = useMemo(
    () =>
      `MXCWPP_HTTP_SERVER=${httpVal} MXCWPP_AGENT_SERVER=${grpcVal} bash -c "$(curl -fsSL http://${curlBase}/agent/install.sh)"`,
    [httpVal, grpcVal, curlBase],
  );

  const manualInstall = useMemo(() => {
    const arch = "amd64";
    return pkgType === "rpm"
      ? `curl -fsSL -o mxcwpp-agent.rpm http://${httpVal}/api/v1/agent/download/rpm/${arch} && yum install -y ./mxcwpp-agent.rpm && rm -f mxcwpp-agent.rpm`
      : `curl -fsSL -o mxcwpp-agent.deb http://${httpVal}/api/v1/agent/download/deb/${arch} && apt-get install -y ./mxcwpp-agent.deb && rm -f mxcwpp-agent.deb`;
  }, [httpVal, pkgType]);

  const uninstall = `bash -c "$(curl -fsSL http://${curlBase}/agent/uninstall.sh)"`;
  const statusCmd = "systemctl status mxcwpp-agent";
  const logCmd = "journalctl -u mxcwpp-agent -n 50 --no-pager | grep -i connect";

  return (
    <div className="space-y-4">
      {/* 支持的操作系统 */}
      <Card>
        <CardHeader title={t("operations.install.supportedOs")} />
        <div className="flex flex-wrap gap-x-6 gap-y-3 px-5 pb-5">
          {SUPPORTED_OS.map((os) => (
            <div key={os.badge} className="flex items-center gap-2 text-sm">
              <span className="inline-block min-w-[64px] rounded-control bg-surface-muted px-2 py-1 text-center text-xs font-semibold text-muted">
                {os.badge}
              </span>
              <span className="text-ink">{os.text}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* 服务器地址配置 */}
      <Card>
        <CardHeader title={t("operations.install.serverConfig")} />
        <div className="space-y-4 px-5 pb-5">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <FormField label={t("operations.install.fieldHttpAddr")}>
              <Input
                value={httpAddr}
                onChange={(e) => setHttpAddr(e.target.value)}
                placeholder={t("operations.install.httpPlaceholder")}
              />
            </FormField>
            <FormField label={t("operations.install.fieldGrpcAddr")}>
              <Input
                value={grpcAddr}
                onChange={(e) => setGrpcAddr(e.target.value)}
                placeholder={t("operations.install.grpcPlaceholder")}
              />
            </FormField>
          </div>
          {isLocalhost && (
            <p className="text-sm text-warning">
              {t("operations.install.localhostHint")}
            </p>
          )}
          <p className="text-xs text-muted">
            {t("operations.install.addrHint")}
          </p>
        </div>
      </Card>

      {/* 一键安装 */}
      <Card>
        <CardHeader title={t("operations.install.autoInstall")} />
        <div className="space-y-2 px-5 pb-5">
          <p className="text-sm text-muted">{t("operations.install.autoInstallHint")}</p>
          <CommandBlock command={autoInstall} t={t} />
        </div>
      </Card>

      {/* 手动安装 */}
      <Card>
        <CardHeader title={t("operations.install.manualInstall")} />
        <div className="space-y-3 px-5 pb-5">
          <Tabs items={PKG_TABS} active={pkgType} onChange={setPkgType} />
          <CommandBlock command={manualInstall} t={t} />
        </div>
      </Card>

      {/* 验证安装 */}
      <Card>
        <CardHeader title={t("operations.install.verifyInstall")} />
        <div className="space-y-3 px-5 pb-5">
          <div className="space-y-1.5">
            <p className="text-sm text-muted">{t("operations.install.statusHint")}</p>
            <CommandBlock command={statusCmd} t={t} />
          </div>
          <div className="space-y-1.5">
            <p className="text-sm text-muted">{t("operations.install.logHint")}</p>
            <CommandBlock command={logCmd} t={t} />
          </div>
        </div>
      </Card>

      {/* 卸载 */}
      <Card>
        <CardHeader title={t("operations.install.uninstall")} />
        <div className="space-y-2 px-5 pb-5">
          <CommandBlock command={uninstall} t={t} />
        </div>
      </Card>
    </div>
  );
}
