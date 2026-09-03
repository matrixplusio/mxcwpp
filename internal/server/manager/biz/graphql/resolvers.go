package graphql

import (
	"context"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RegisterDefault 注册默认 resolver (hosts/alerts/vulns/host/alertById).
//
// 所有 resolver 必须从 req.TenantID 过滤, 防越租户.
func RegisterDefault(reg *Registry, db *gorm.DB) {
	reg.Register("hosts", hostsResolver(db))
	reg.Register("host", hostByIDResolver(db))
	reg.Register("alerts", alertsResolver(db))
	reg.Register("alert", alertByIDResolver(db))
	reg.Register("vulns", vulnsResolver(db))
	reg.Register("introspection", introspectionResolver(reg))
}

func hostsResolver(db *gorm.DB) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		if req.TenantID == "" {
			return nil, ErrUnauthorized
		}
		limit := VarInt(req, "limit", 50)
		if limit > 200 {
			limit = 200
		}
		status := VarString(req, "status")
		q := db.WithContext(ctx).Model(&model.Host{}).Where("tenant_id = ?", req.TenantID)
		if status != "" {
			q = q.Where("status = ?", status)
		}
		var rows []model.Host
		if err := q.Limit(limit).Find(&rows).Error; err != nil {
			return nil, err
		}
		return rows, nil
	}
}

func hostByIDResolver(db *gorm.DB) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		if req.TenantID == "" {
			return nil, ErrUnauthorized
		}
		id := VarString(req, "id")
		if id == "" {
			return nil, errInvalidVar("id")
		}
		var row model.Host
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND id = ?", req.TenantID, id).
			First(&row).Error; err != nil {
			return nil, err
		}
		return row, nil
	}
}

func alertsResolver(db *gorm.DB) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		if req.TenantID == "" {
			return nil, ErrUnauthorized
		}
		limit := VarInt(req, "limit", 50)
		if limit > 200 {
			limit = 200
		}
		severity := VarString(req, "severity")
		status := VarString(req, "status")
		q := db.WithContext(ctx).Model(&model.Alert{}).Where("tenant_id = ?", req.TenantID)
		if severity != "" {
			q = q.Where("severity = ?", severity)
		}
		if status != "" {
			q = q.Where("status = ?", status)
		}
		var rows []model.Alert
		if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
			return nil, err
		}
		return rows, nil
	}
}

func alertByIDResolver(db *gorm.DB) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		if req.TenantID == "" {
			return nil, ErrUnauthorized
		}
		id := VarString(req, "id")
		if id == "" {
			return nil, errInvalidVar("id")
		}
		var row model.Alert
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND id = ?", req.TenantID, id).
			First(&row).Error; err != nil {
			return nil, err
		}
		return row, nil
	}
}

func vulnsResolver(db *gorm.DB) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		if req.TenantID == "" {
			return nil, ErrUnauthorized
		}
		limit := VarInt(req, "limit", 50)
		if limit > 200 {
			limit = 200
		}
		severity := VarString(req, "severity")
		q := db.WithContext(ctx).Model(&model.Vulnerability{}).Where("tenant_id = ?", req.TenantID)
		if severity != "" {
			q = q.Where("severity = ?", severity)
		}
		var rows []model.Vulnerability
		if err := q.Order("cvss_score DESC").Limit(limit).Find(&rows).Error; err != nil {
			return nil, err
		}
		return rows, nil
	}
}

func introspectionResolver(reg *Registry) Resolver {
	return func(ctx context.Context, req *Request) (any, error) {
		return map[string]any{"operations": reg.Operations()}, nil
	}
}

func errInvalidVar(name string) error {
	return &validationError{Field: name}
}

type validationError struct {
	Field string
}

func (e *validationError) Error() string {
	return "invalid or missing variable: " + e.Field
}
