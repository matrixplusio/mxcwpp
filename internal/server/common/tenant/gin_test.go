package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type fakeHost struct {
	HostID   string `gorm:"primaryKey"`
	TenantID string
	Name     string
}

func (fakeHost) TableName() string { return "fake_hosts" }

func newTenantTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&fakeHost{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	rows := []fakeHost{
		{HostID: "h-a-1", TenantID: "t-a", Name: "Alpha-1"},
		{HostID: "h-a-2", TenantID: "t-a", Name: "Alpha-2"},
		{HostID: "h-b-1", TenantID: "t-b", Name: "Bravo-1"},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db
}

func TestGinScope_IsolatesTenants(t *testing.T) {
	t.Parallel()
	db := newTenantTestDB(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{ID: "t-a"})
		c.Next()
	})
	r.GET("/hosts", func(c *gin.Context) {
		var hosts []fakeHost
		if err := db.Scopes(GinScope(c)).Find(&hosts).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": len(hosts), "hosts": hosts})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hosts", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	// 租户 A 只能看到 2 条记录
	if !contains(w.Body.String(), `"count":2`) {
		t.Fatalf("expected count=2 (only tenant A rows), got body=%s", w.Body.String())
	}
	if contains(w.Body.String(), "Bravo") {
		t.Fatalf("tenant A leaked tenant B's row! body=%s", w.Body.String())
	}
}

func TestGinScope_CrossTenantLookupReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := newTenantTestDB(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{ID: "t-a"}) // 租户 A
		c.Next()
	})
	r.GET("/hosts/:id", func(c *gin.Context) {
		var host fakeHost
		// 故意查询租户 B 的主机
		err := db.Scopes(GinScope(c)).Where("host_id = ?", c.Param("id")).First(&host).Error
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"err": "not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"host": host})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hosts/h-b-1", nil) // 跨租户查 B
	r.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404 (cross-tenant blocked), got %d body=%s", w.Code, w.Body.String())
	}
}

func TestGinScope_PlatformAdminSeesAllTenants(t *testing.T) {
	t.Parallel()
	db := newTenantTestDB(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{IsPlatformAdmin: true}) // 平台超管,无 tenant
		c.Next()
	})
	r.GET("/hosts", func(c *gin.Context) {
		var hosts []fakeHost
		_ = db.Scopes(GinScope(c)).Find(&hosts).Error
		c.JSON(http.StatusOK, gin.H{"count": len(hosts)})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hosts", nil)
	r.ServeHTTP(w, req)

	if !contains(w.Body.String(), `"count":3`) {
		t.Fatalf("platform admin should see all 3 rows across tenants, body=%s", w.Body.String())
	}
}

func TestGinScopeStrict_PlatformAdminMustHaveTenantID(t *testing.T) {
	t.Parallel()
	db := newTenantTestDB(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// 平台超管但没选 tenant —— Strict 应该报 ErrMissingTenant
		SetIdentity(c, Identity{IsPlatformAdmin: true})
		c.Next()
	})
	r.GET("/hosts", func(c *gin.Context) {
		var hosts []fakeHost
		err := db.Scopes(GinScopeStrict(c)).Find(&hosts).Error
		if err == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"err": "expected error"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hosts", nil)
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 (missing tenant under strict), got %d body=%s", w.Code, w.Body.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
