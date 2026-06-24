package biz

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

//go:embed manifests/trivy-operator.yaml
var trivyOperatorManifest []byte

const (
	trivyOperatorNamespace  = "trivy-system"
	trivyOperatorDeployment = "trivy-operator"
	trivyOperatorVersion    = "0.23.0" // 内嵌 manifest 实际部署的 operator 镜像 tag
	scannerFieldManager     = "mxcwpp"
)

// trivyImageRegistries manifest 默认引用的上游镜像仓库前缀（air-gap 重写时整体替换为客户私有 registry）
var trivyImageRegistries = []string{"mirror.gcr.io/aquasec", "ghcr.io/aquasecurity"}

// vulnReportGVR trivy-operator 漏洞报告 CRD
var vulnReportGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

// KubeVulnOperator 管理目标集群内 trivy-operator 扫描器的全生命周期
type KubeVulnOperator struct {
	db     *gorm.DB
	logger *zap.Logger
	kube   *KubeClientManager
}

// NewKubeVulnOperator 创建扫描器生命周期管理器
func NewKubeVulnOperator(db *gorm.DB, logger *zap.Logger, kube *KubeClientManager) *KubeVulnOperator {
	return &KubeVulnOperator{db: db, logger: logger, kube: kube}
}

// PreflightResult 安装前预检结果
type PreflightResult struct {
	K8sVersion      string `json:"k8sVersion"`
	CanAutoInstall  bool   `json:"canAutoInstall"`  // 我方 kubeconfig 是否有权限自动安装（建 CRD）
	NamespaceExists bool   `json:"namespaceExists"` // trivy-system 是否已存在
	OperatorExists  bool   `json:"operatorExists"`  // operator deployment 是否已存在
	Reason          string `json:"reason"`
}

// ScannerStatus 扫描器运行状态
type ScannerStatus struct {
	State           model.KubeScannerState `json:"state"`
	OperatorVersion string                 `json:"operatorVersion"`
	ReadyReplicas   int32                  `json:"readyReplicas"`
	WebhookEnabled  bool                   `json:"webhookEnabled"`
	LastSyncAt      *model.LocalTime       `json:"lastSyncAt"`
	LastReportCount int                    `json:"lastReportCount"`
	LastError       string                 `json:"lastError"`
}

// InstallOptions 安装参数
type InstallOptions struct {
	ImageRegistry  string // 镜像地址覆盖（air-gap），空=默认 ghcr.io
	WebhookBaseURL string // manager 外部可达 URL（含 token），空=不启用 Push
}

// ---- 客户端 ----

func (o *KubeVulnOperator) clients(clusterID uint) (dynamic.Interface, meta.RESTMapper, error) {
	cfg, err := o.kube.GetRESTConfig(clusterID)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 dynamic 客户端失败: %w", err)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 discovery 客户端失败: %w", err)
	}
	gr, err := restmapper.GetAPIGroupResources(dc)
	if err != nil {
		return nil, nil, fmt.Errorf("获取集群 API 资源失败: %w", err)
	}
	return dyn, restmapper.NewDiscoveryRESTMapper(gr), nil
}

// ---- 预检 ----

// Preflight 安装前检查集群兼容性与我方权限
func (o *KubeVulnOperator) Preflight(ctx context.Context, clusterID uint) (*PreflightResult, error) {
	clientset, err := o.kube.GetClient(clusterID)
	if err != nil {
		return nil, err
	}
	res := &PreflightResult{}

	if sv, e := clientset.Discovery().ServerVersion(); e == nil {
		res.K8sVersion = sv.GitVersion
	}

	// 权限检查：能否创建 CustomResourceDefinition（自动安装的关键权限）
	ssar := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "create",
				Group:    "apiextensions.k8s.io",
				Resource: "customresourcedefinitions",
			},
		},
	}
	if rev, e := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{}); e == nil {
		res.CanAutoInstall = rev.Status.Allowed
		if !rev.Status.Allowed {
			res.Reason = "当前 kubeconfig 无创建 CRD 权限，请使用 manifest 导出方式由集群管理员手动安装"
		}
	} else {
		res.Reason = "权限检查失败: " + e.Error()
	}

	if _, e := clientset.CoreV1().Namespaces().Get(ctx, trivyOperatorNamespace, metav1.GetOptions{}); e == nil {
		res.NamespaceExists = true
	}
	if _, e := clientset.AppsV1().Deployments(trivyOperatorNamespace).Get(ctx, trivyOperatorDeployment, metav1.GetOptions{}); e == nil {
		res.OperatorExists = true
	}
	return res, nil
}

// ---- manifest 渲染 ----

// RenderManifest 返回渲染后的 operator manifest（用于兜底的手动安装路径）
func (o *KubeVulnOperator) RenderManifest(imageRegistry, webhookBaseURL string) ([]byte, error) {
	objs, err := o.renderObjects(imageRegistry, webhookBaseURL)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, obj := range objs {
		data, e := sigsyaml.Marshal(obj.Object)
		if e != nil {
			return nil, e
		}
		buf.WriteString("---\n")
		buf.Write(data)
	}
	return buf.Bytes(), nil
}

func (o *KubeVulnOperator) renderObjects(imageRegistry, webhookBaseURL string) ([]*unstructured.Unstructured, error) {
	raw := trivyOperatorManifest
	if imageRegistry != "" {
		// air-gap：把上游镜像仓库前缀整体替换为客户私有 registry（保留 /aquasec 或 /aquasecurity 路径段）
		reg := strings.TrimRight(imageRegistry, "/")
		for _, up := range trivyImageRegistries {
			suffix := up[strings.LastIndex(up, "/"):] // "/aquasec" 或 "/aquasecurity"
			raw = bytes.ReplaceAll(raw, []byte(up), []byte(reg+suffix))
		}
	}

	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var objs []*unstructured.Unstructured
	for {
		obj := &unstructured.Unstructured{}
		if err := dec.Decode(obj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("解析 operator manifest 失败: %w", err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		objs = append(objs, obj)
	}

	// 启用 Push：把 webhook URL 注入 operator Deployment 环境变量
	if webhookBaseURL != "" {
		for _, obj := range objs {
			if err := injectWebhookEnv(obj, webhookBaseURL); err != nil {
				return nil, err
			}
		}
	}

	sortObjectsByKind(objs)
	return objs, nil
}

func kindApplyPriority(kind string) int {
	switch kind {
	case "Namespace":
		return 0
	case "CustomResourceDefinition":
		return 1
	case "ServiceAccount":
		return 2
	case "ClusterRole", "Role":
		return 3
	case "ClusterRoleBinding", "RoleBinding":
		return 4
	case "ConfigMap", "Secret":
		return 5
	case "Service":
		return 6
	case "Deployment":
		return 7
	}
	return 8
}

func sortObjectsByKind(objs []*unstructured.Unstructured) {
	sort.SliceStable(objs, func(i, j int) bool {
		return kindApplyPriority(objs[i].GetKind()) < kindApplyPriority(objs[j].GetKind())
	})
}

func injectWebhookEnv(obj *unstructured.Unstructured, url string) error {
	if obj.GetKind() != "Deployment" || obj.GetName() != trivyOperatorDeployment {
		return nil
	}
	containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if err != nil || !found || len(containers) == 0 {
		return fmt.Errorf("operator deployment 容器定义缺失")
	}
	c0, ok := containers[0].(map[string]any)
	if !ok {
		return fmt.Errorf("operator deployment 容器格式异常")
	}
	env, _, _ := unstructured.NestedSlice(c0, "env")
	env = upsertEnv(env, "OPERATOR_WEBHOOK_BROADCAST_URL", url)
	env = upsertEnv(env, "OPERATOR_WEBHOOK_BROADCAST_TIMEOUT", "30s")
	c0["env"] = env
	containers[0] = c0
	return unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers")
}

func upsertEnv(env []any, name, value string) []any {
	for i, e := range env {
		if m, ok := e.(map[string]any); ok {
			if n, _ := m["name"].(string); n == name {
				m["value"] = value
				delete(m, "valueFrom")
				env[i] = m
				return env
			}
		}
	}
	return append(env, map[string]any{"name": name, "value": value})
}

// ---- 安装 / 卸载 ----

// Install 自动安装 operator（server-side apply 内嵌 manifest）
func (o *KubeVulnOperator) Install(ctx context.Context, clusterID uint, opts InstallOptions) error {
	pre, err := o.Preflight(ctx, clusterID)
	if err != nil {
		return err
	}
	if !pre.CanAutoInstall {
		return fmt.Errorf("无法自动安装: %s", pre.Reason)
	}

	o.upsertScanner(clusterID, func(s *model.KubeScanner) {
		s.State = model.ScannerStateInstalling
		s.OperatorVersion = trivyOperatorVersion
		s.ImageRegistry = opts.ImageRegistry
		s.WebhookEnabled = opts.WebhookBaseURL != ""
		s.LastError = ""
	})

	dyn, mapper, err := o.clients(clusterID)
	if err != nil {
		o.markError(clusterID, err)
		return err
	}

	objs, err := o.renderObjects(opts.ImageRegistry, opts.WebhookBaseURL)
	if err != nil {
		o.markError(clusterID, err)
		return err
	}

	for _, obj := range objs {
		if err := applyObject(ctx, dyn, mapper, obj); err != nil {
			wrapped := fmt.Errorf("应用 %s/%s 失败: %w", obj.GetKind(), obj.GetName(), err)
			o.markError(clusterID, wrapped)
			return wrapped
		}
	}

	o.logger.Info("trivy-operator 安装完成（等待就绪）", zap.Uint("clusterID", clusterID))
	return nil
}

func applyObject(ctx context.Context, dyn dynamic.Interface, mapper meta.RESTMapper, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("解析资源映射失败: %w", err)
	}

	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = trivyOperatorNamespace
		}
		dr = dyn.Resource(mapping.Resource).Namespace(ns)
	} else {
		dr = dyn.Resource(mapping.Resource)
	}

	data, err := obj.MarshalJSON()
	if err != nil {
		return err
	}
	force := true
	_, err = dr.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: scannerFieldManager,
		Force:        &force,
	})
	return err
}

// Uninstall 卸载 operator（删 operator + CRD + ns，集群内 report 随 CRD 级联清除）
func (o *KubeVulnOperator) Uninstall(ctx context.Context, clusterID uint) error {
	o.upsertScanner(clusterID, func(s *model.KubeScanner) { s.State = model.ScannerStateUninstalling })

	dyn, mapper, err := o.clients(clusterID)
	if err != nil {
		o.markError(clusterID, err)
		return err
	}

	objs, err := o.renderObjects("", "")
	if err != nil {
		o.markError(clusterID, err)
		return err
	}
	// 逆序删除（Deployment 先，Namespace/CRD 最后）
	sort.SliceStable(objs, func(i, j int) bool {
		return kindApplyPriority(objs[i].GetKind()) > kindApplyPriority(objs[j].GetKind())
	})

	for _, obj := range objs {
		if err := deleteObject(ctx, dyn, mapper, obj); err != nil && !apierrors.IsNotFound(err) {
			o.logger.Warn("删除 operator 资源失败", zap.String("kind", obj.GetKind()), zap.String("name", obj.GetName()), zap.Error(err))
		}
	}

	o.upsertScanner(clusterID, func(s *model.KubeScanner) {
		s.State = model.ScannerStateNotInstalled
		s.WebhookEnabled = false
		s.LastError = ""
	})
	o.logger.Info("trivy-operator 已卸载", zap.Uint("clusterID", clusterID))
	return nil
}

func deleteObject(ctx context.Context, dyn dynamic.Interface, mapper meta.RESTMapper, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return err
	}
	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = trivyOperatorNamespace
		}
		dr = dyn.Resource(mapping.Resource).Namespace(ns)
	} else {
		dr = dyn.Resource(mapping.Resource)
	}
	return dr.Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
}

// ---- 状态 / 健康 ----

// Status 返回扫描器运行状态（含 operator deployment 实时健康，带漂移检测）
// 即使无 DB 记录也会查询集群，以发现由运维 manifest 路径外部安装的 operator 并反向重建记录。
func (o *KubeVulnOperator) Status(ctx context.Context, clusterID uint) (*ScannerStatus, error) {
	var rec model.KubeScanner
	recErr := o.db.Where("cluster_id = ?", clusterID).First(&rec).Error
	if recErr != nil && recErr != gorm.ErrRecordNotFound {
		return nil, recErr
	}
	hasRec := recErr == nil
	if !hasRec {
		rec.State = model.ScannerStateNotInstalled
	}

	status := &ScannerStatus{
		State:           rec.State,
		OperatorVersion: rec.OperatorVersion,
		WebhookEnabled:  rec.WebhookEnabled,
		LastSyncAt:      rec.LastSyncAt,
		LastReportCount: rec.LastReportCount,
		LastError:       rec.LastError,
	}

	clientset, err := o.kube.GetClient(clusterID)
	if err != nil {
		return status, nil // 集群不可达，返回 DB 记录状态
	}
	dep, err := clientset.AppsV1().Deployments(trivyOperatorNamespace).Get(ctx, trivyOperatorDeployment, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// 漂移：DB 记录已安装但集群内 operator 消失
		if rec.State == model.ScannerStateReady || rec.State == model.ScannerStateInstalling {
			status.State = model.ScannerStateDegraded
			o.upsertScanner(clusterID, func(s *model.KubeScanner) { s.State = model.ScannerStateDegraded })
		}
		return status, nil
	}
	if err != nil {
		return status, nil
	}

	status.ReadyReplicas = dep.Status.ReadyReplicas
	newState := model.ScannerStateDegraded
	if dep.Status.ReadyReplicas >= 1 {
		newState = model.ScannerStateReady
	}
	status.State = newState
	// 反向重建/纠正记录：发现外部安装(无记录) 或 状态变更，均落库（卸载中除外）
	if (!hasRec || rec.State != newState) && rec.State != model.ScannerStateUninstalling {
		o.upsertScanner(clusterID, func(s *model.KubeScanner) {
			s.State = newState
			if s.OperatorVersion == "" {
				s.OperatorVersion = trivyOperatorVersion
			}
		})
	}
	return status, nil
}

// ---- 结果同步（Pull）----

// SyncReports 通过 LIST VulnerabilityReport CRD 全量同步落库（快照覆盖）
func (o *KubeVulnOperator) SyncReports(ctx context.Context, clusterID uint) (int, error) {
	dyn, _, err := o.clients(clusterID)
	if err != nil {
		return 0, err
	}

	var items []unstructured.Unstructured
	cont := ""
	for {
		list, err := dyn.Resource(vulnReportGVR).Namespace("").List(ctx, metav1.ListOptions{Limit: 200, Continue: cont})
		if err != nil {
			o.markError(clusterID, err)
			return 0, fmt.Errorf("列出 VulnerabilityReport 失败: %w", err)
		}
		items = append(items, list.Items...)
		cont = list.GetContinue()
		if cont == "" {
			break
		}
	}

	// 事务内快照覆盖：清本集群旧的 source=cluster 记录，再写入当前快照
	err = o.db.Transaction(func(tx *gorm.DB) error {
		if e := deleteClusterScans(tx, clusterID, nil); e != nil {
			return e
		}
		for i := range items {
			scan, vulns := parseVulnReport(clusterID, &items[i])
			if scan == nil {
				continue
			}
			if e := insertScan(tx, scan, vulns); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		o.markError(clusterID, err)
		return 0, fmt.Errorf("同步落库失败: %w", err)
	}

	now := model.Now()
	count := len(items)
	o.upsertScanner(clusterID, func(s *model.KubeScanner) {
		s.LastSyncAt = &now
		s.LastReportCount = count
		s.LastError = ""
		// 同步成功说明 operator 正常产出报告 → 置 ready（卸载中除外）
		if s.State != model.ScannerStateUninstalling {
			s.State = model.ScannerStateReady
		}
	})
	o.logger.Info("集群漏洞报告同步完成", zap.Uint("clusterID", clusterID), zap.Int("reports", count))
	return count, nil
}

// IngestReport 处理 Push（webhook）来的单个报告，按镜像 upsert
func (o *KubeVulnOperator) IngestReport(clusterID uint, u *unstructured.Unstructured) error {
	scan, vulns := parseVulnReport(clusterID, u)
	if scan == nil {
		return fmt.Errorf("报告解析为空")
	}
	return o.db.Transaction(func(tx *gorm.DB) error {
		if e := deleteClusterScans(tx, clusterID, &scan.Image); e != nil {
			return e
		}
		return insertScan(tx, scan, vulns)
	})
}

// ---- 解析（Pull / Push 共用）----

func parseVulnReport(clusterID uint, u *unstructured.Unstructured) (*model.ImageScan, []model.ImageVulnerability) {
	obj := u.Object
	repo, _, _ := unstructured.NestedString(obj, "report", "artifact", "repository")
	if repo == "" {
		return nil, nil
	}
	tag, _, _ := unstructured.NestedString(obj, "report", "artifact", "tag")
	digest, _, _ := unstructured.NestedString(obj, "report", "artifact", "digest")
	server, _, _ := unstructured.NestedString(obj, "report", "registry", "server")
	osFamily, _, _ := unstructured.NestedString(obj, "report", "os", "family")
	osName, _, _ := unstructured.NestedString(obj, "report", "os", "name")
	crit, _, _ := unstructured.NestedInt64(obj, "report", "summary", "criticalCount")
	high, _, _ := unstructured.NestedInt64(obj, "report", "summary", "highCount")

	cid := clusterID
	now := model.Now()
	scan := &model.ImageScan{
		Image:       buildImageName(server, repo, tag, digest),
		ClusterID:   &cid,
		Source:      "cluster",
		Digest:      digest,
		OS:          strings.TrimSpace(osFamily + " " + osName),
		Status:      "done",
		CriticalCnt: int(crit),
		HighCnt:     int(high),
		ScannedAt:   &now,
	}

	vulnsRaw, _, _ := unstructured.NestedSlice(obj, "report", "vulnerabilities")
	var vulns []model.ImageVulnerability
	seen := make(map[string]struct{})
	for _, vr := range vulnsRaw {
		vm, ok := vr.(map[string]any)
		if !ok {
			continue
		}
		id, _ := vm["vulnerabilityID"].(string)
		pkg, _ := vm["resource"].(string)
		key := id + "|" + pkg
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		inst, _ := vm["installedVersion"].(string)
		fixed, _ := vm["fixedVersion"].(string)
		sev, _ := vm["severity"].(string)
		title, _ := vm["title"].(string)
		vulns = append(vulns, model.ImageVulnerability{
			CveID:        id,
			Package:      pkg,
			Version:      inst,
			FixedVersion: fixed,
			Severity:     sev,
			Title:        title,
		})
	}
	scan.TotalVulns = len(vulns)
	return scan, vulns
}

func buildImageName(server, repo, tag, digest string) string {
	name := repo
	if server != "" {
		name = strings.TrimRight(server, "/") + "/" + repo
	}
	switch {
	case tag != "":
		return name + ":" + tag
	case digest != "":
		return name + "@" + digest
	default:
		return name
	}
}

// ---- DB 辅助 ----

func deleteClusterScans(tx *gorm.DB, clusterID uint, image *string) error {
	q := tx.Model(&model.ImageScan{}).Where("cluster_id = ? AND source = ?", clusterID, "cluster")
	if image != nil {
		q = q.Where("image = ?", *image)
	}
	var ids []uint
	if err := q.Pluck("id", &ids).Error; err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := tx.Where("image_scan_id IN ?", ids).Delete(&model.ImageVulnerability{}).Error; err != nil {
		return err
	}
	return tx.Where("id IN ?", ids).Delete(&model.ImageScan{}).Error
}

func insertScan(tx *gorm.DB, scan *model.ImageScan, vulns []model.ImageVulnerability) error {
	if err := tx.Create(scan).Error; err != nil {
		return err
	}
	if len(vulns) == 0 {
		return nil
	}
	for i := range vulns {
		vulns[i].ImageScanID = scan.ID
	}
	return tx.CreateInBatches(vulns, 100).Error
}

func (o *KubeVulnOperator) upsertScanner(clusterID uint, mutate func(*model.KubeScanner)) {
	var rec model.KubeScanner
	err := o.db.Where("cluster_id = ?", clusterID).First(&rec).Error
	if err == gorm.ErrRecordNotFound {
		rec = model.KubeScanner{ClusterID: clusterID, State: model.ScannerStateNotInstalled}
		mutate(&rec)
		if e := o.db.Create(&rec).Error; e != nil {
			o.logger.Warn("创建扫描器记录失败", zap.Error(e))
		}
		return
	}
	if err != nil {
		o.logger.Warn("读取扫描器记录失败", zap.Error(err))
		return
	}
	mutate(&rec)
	if e := o.db.Save(&rec).Error; e != nil {
		o.logger.Warn("更新扫描器记录失败", zap.Error(e))
	}
}

func (o *KubeVulnOperator) markError(clusterID uint, err error) {
	o.upsertScanner(clusterID, func(s *model.KubeScanner) {
		s.LastError = err.Error()
		if s.State == model.ScannerStateInstalling {
			s.State = model.ScannerStateDegraded
		}
	})
}

var _ = time.Second
