package model

import (
	"testing"

	"gorm.io/gorm"
)

// TestNoAfterSaveHooks 同步到 CH 的模型不得挂 AfterSave。
//
// GORM 在 create 与 update 之后都会调用 AfterSave，与 AfterCreate / AfterUpdate
// 完全重叠。三个钩子都挂上同一个同步函数，等于每写一次就往 ClickHouse 插两行。
//
// 这个错误不会表现为数据错误：CH 侧是 ReplacingMergeTree，重复行最终被合并掉。
// 它只表现为 part 数量翻倍——每次写入都多出一个单行 part，
// 合并压力全部来自这里。
func TestNoAfterSaveHooks(t *testing.T) {
	type afterSaver interface{ AfterSave(*gorm.DB) error }

	for name, m := range map[string]any{
		"Alert":             &Alert{},
		"Vulnerability":     &Vulnerability{},
		"HostVulnerability": &HostVulnerability{},
	} {
		if _, has := m.(afterSaver); has {
			t.Errorf("%s 挂了 AfterSave；它与 AfterCreate / AfterUpdate 重叠，"+
				"会让每次写入向 ClickHouse 插两行", name)
		}
	}
}

// TestCHSyncHooksStillPresent 反向校验：两个该有的钩子不能一起被删掉。
//
// 少了它们，MySQL 写入不再同步到 CH，而查询侧照常从 CH 读——
// 表面上一切正常，只是数据停在删除那一刻。
func TestCHSyncHooksStillPresent(t *testing.T) {
	type creator interface{ AfterCreate(*gorm.DB) error }
	type updater interface{ AfterUpdate(*gorm.DB) error }

	for name, m := range map[string]any{
		"Alert":             &Alert{},
		"Vulnerability":     &Vulnerability{},
		"HostVulnerability": &HostVulnerability{},
	} {
		if _, ok := m.(creator); !ok {
			t.Errorf("%s 缺少 AfterCreate，新建的记录不会同步到 ClickHouse", name)
		}
		if _, ok := m.(updater); !ok {
			t.Errorf("%s 缺少 AfterUpdate，更新不会同步到 ClickHouse", name)
		}
	}
}
