# UI 深度巡检报告 (42 场景, 累计 23 tabs 点击)

- PASS: 41 / WARN: 1 / FAIL: 0

| Scenario | Status | tabs | 5xx | 4xx | console | notes |
|---|---|---|---|---|---|---|
| detail alerts→detail | PASS | 0 | 0 | 0 | 0 | no detail row found by .ant-table a[href*="/alerts/"], a:has-text("详情") |
| detail hosts→detail | PASS | 7 | 0 | 0 | 0 | detail tabs count=7 |
| detail kube-clusters→detail | WARN | 5 | 0 | 3 | 6 | detail tabs count=5 |
| detail policies→detail | PASS | 0 | 0 | 0 | 0 | no detail row found by .ant-table a[href*="/policies/"], a:has-text("详情") |
| detail policy-groups→rules | PASS | 0 | 0 | 0 | 0 | no detail row found by .ant-table a, a:has-text("规则"), a:has-text("详情") |
| detail remediation-tasks→detail | PASS | 0 | 0 | 0 | 0 | detail tabs count=0 |
| detail vuln-bulletins→detail | PASS | 3 | 0 | 0 | 0 | detail tabs count=3 |
| detail vuln-list→detail | PASS | 2 | 0 | 0 | 0 | detail tabs count=2 |
| modal /business-lines | PASS | 0 | 0 | 0 | 0 | modal opened=true |
| modal /policy-groups | PASS | 0 | 0 | 0 | 0 | modal opened=true |
| modal /system/data-retention | PASS | 0 | 0 | 0 | 0 | no "新建" trigger |
| modal /system/feature-flags | PASS | 0 | 0 | 0 | 0 | no "新建" trigger |
| modal /system/notification | PASS | 0 | 0 | 0 | 0 | modal opened=true |
| modal /users | PASS | 0 | 0 | 0 | 0 | modal opened=true |
| modal /vuln-data-sources | PASS | 0 | 0 | 0 | 0 | no "新建" trigger |
| modal /whitelist | PASS | 0 | 0 | 0 | 0 | modal opened=true |
| rasp /rasp/alarms | PASS | 0 | 0 | 0 | 0 | DOM ok=true |
| rasp /rasp/apps | PASS | 0 | 0 | 0 | 0 | DOM ok=true |
| rasp /rasp/config | PASS | 0 | 0 | 0 | 0 | DOM ok=true |
| rasp /rasp/vulns | PASS | 0 | 0 | 0 | 0 | DOM ok=true |
| tabs /ad-audit | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /anomaly | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /bde | PASS | 2 | 0 | 0 | 0 | tab count=2 |
| tabs /detection/rules | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /edr/events | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /fim/dashboard | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /honeypot | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /hunting | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /kube/baseline | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /kube/clusters | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /kube/image-scan | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /sbom-import | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /storylines | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /system/components | PASS | 4 | 0 | 0 | 0 | tab count=4 |
| tabs /system/data-retention | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /system/feature-flags | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /system/host-monitor | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /system/inspection | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /system/service-monitor | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /threat-intel | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /vuln-bulletins | PASS | 0 | 0 | 0 | 0 | tab count=0 |
| tabs /vuln-remediation | PASS | 0 | 0 | 0 | 0 | tab count=0 |

## 详细 (FAIL/WARN)

### detail kube-clusters→detail (WARN)
- console:
  - Failed to load resource: the server responded with a status of 503 (Service Unavailable)
  - HTTP Error: AxiosError
  - Failed to load resource: the server responded with a status of 503 (Service Unavailable)
  - HTTP Error: AxiosError
  - Failed to load resource: the server responded with a status of 503 (Service Unavailable)
- 4xx:
  - 503 /api/v1/kube/clusters/1/pods?page=1&page_size=20
  - 503 /api/v1/kube/clusters/1/nodes
  - 503 /api/v1/kube/clusters/1/workloads
- notes:
  - detail tabs count=5