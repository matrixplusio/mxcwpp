// Package main 提供检测规则测试 CLI 工具
// 用法：go run ./cmd/tools/ruletest --rules rules/ --tests testcases/
//
// 规则文件格式（同 rulesync YAML）：
//
//	rules:
//	  - name: reverse_shell
//	    expression: 'exe == "/bin/bash" && remote_addr != ""'
//	    severity: critical
//	    data_types: [3000]
//
// 测试用例文件格式：
//
//	tests:
//	  - name: "反弹 Shell 应命中"
//	    data_type: 3000
//	    fields:
//	      exe: "/bin/bash"
//	      remote_addr: "1.2.3.4"
//	    expect_match: ["reverse_shell"]
//	  - name: "正常 bash 不命中"
//	    data_type: 3000
//	    fields:
//	      exe: "/bin/bash"
//	      remote_addr: ""
//	    expect_not_match: ["reverse_shell"]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// --- YAML 结构体 ---

type rulesYAMLFile struct {
	Rules []ruleEntry `mapstructure:"rules"`
}

type ruleEntry struct {
	Name        string   `mapstructure:"name"`
	Expression  string   `mapstructure:"expression"`
	Severity    string   `mapstructure:"severity"`
	Category    string   `mapstructure:"category"`
	MitreID     string   `mapstructure:"mitre_id"`
	DataTypes   []string `mapstructure:"data_types"`
	Description string   `mapstructure:"description"`
}

type testsYAMLFile struct {
	Tests []testCase `mapstructure:"tests"`
}

type testCase struct {
	Name           string            `mapstructure:"name"`
	DataType       int32             `mapstructure:"data_type"`
	Fields         map[string]string `mapstructure:"fields"`
	ExpectMatch    []string          `mapstructure:"expect_match"`
	ExpectNotMatch []string          `mapstructure:"expect_not_match"`
}

func main() {
	rulesPath := flag.String("rules", "", "规则 YAML 文件或目录")
	testsPath := flag.String("tests", "", "测试用例 YAML 文件或目录")
	verbose := flag.Bool("v", false, "显示详细输出")
	flag.Parse()

	if *rulesPath == "" || *testsPath == "" {
		fmt.Fprintln(os.Stderr, "用法: ruletest --rules <规则路径> --tests <测试用例路径>")
		os.Exit(1)
	}

	// 1. 加载规则
	rules, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已加载 %d 条规则\n", len(rules))

	// 2. 创建内存引擎
	logger, _ := zap.NewDevelopment()
	if !*verbose {
		logger = zap.NewNop()
	}
	engine, err := celengine.NewInMemory(logger, rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建 CEL 引擎失败: %v\n", err)
		os.Exit(1)
	}

	// 3. 加载测试用例
	tests, err := loadTests(*testsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载测试用例失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已加载 %d 条测试用例\n\n", len(tests))

	// 4. 执行测试
	passed, failed := 0, 0
	for _, tc := range tests {
		ok, msg := runTest(engine, &tc)
		if ok {
			passed++
			if *verbose {
				fmt.Printf("  PASS  %s\n", tc.Name)
			}
		} else {
			failed++
			fmt.Printf("  FAIL  %s\n        %s\n", tc.Name, msg)
		}
	}

	// 5. 汇总
	fmt.Printf("\n--- 结果: %d 通过, %d 失败, 共 %d ---\n", passed, failed, passed+failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// runTest 执行单个测试用例，返回是否通过及失败原因
func runTest(engine *celengine.Engine, tc *testCase) (bool, string) {
	matched := engine.Evaluate(tc.DataType, tc.Fields)

	matchedNames := make(map[string]bool, len(matched))
	for _, r := range matched {
		matchedNames[r.Name] = true
	}

	// 检查 expect_match
	for _, name := range tc.ExpectMatch {
		if !matchedNames[name] {
			nameList := make([]string, 0, len(matchedNames))
			for n := range matchedNames {
				nameList = append(nameList, n)
			}
			return false, fmt.Sprintf("期望匹配 %q 但未命中 (实际匹配: [%s])", name, strings.Join(nameList, ", "))
		}
	}

	// 检查 expect_not_match
	for _, name := range tc.ExpectNotMatch {
		if matchedNames[name] {
			return false, fmt.Sprintf("期望不匹配 %q 但命中了", name)
		}
	}

	return true, ""
}

// --- 文件加载 ---

func loadRules(path string) ([]model.DetectionRule, error) {
	files, err := resolveYAMLFiles(path)
	if err != nil {
		return nil, err
	}

	var rules []model.DetectionRule
	idCounter := uint(1)

	for _, f := range files {
		entries, err := parseRuleFile(f)
		if err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", f, err)
		}
		for _, e := range entries {
			rules = append(rules, model.DetectionRule{
				ID:          idCounter,
				Name:        e.Name,
				Expression:  e.Expression,
				Severity:    e.Severity,
				Category:    e.Category,
				MitreID:     e.MitreID,
				DataTypes:   model.StringArray(e.DataTypes),
				Description: e.Description,
				Enabled:     true,
			})
			idCounter++
		}
	}
	return rules, nil
}

func loadTests(path string) ([]testCase, error) {
	files, err := resolveYAMLFiles(path)
	if err != nil {
		return nil, err
	}

	var tests []testCase
	for _, f := range files {
		v := viper.New()
		v.SetConfigType("yaml")
		v.SetConfigFile(f)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("读取 %s 失败: %w", f, err)
		}
		var file testsYAMLFile
		if err := v.Unmarshal(&file); err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", f, err)
		}
		tests = append(tests, file.Tests...)
	}
	return tests, nil
}

func parseRuleFile(path string) ([]ruleEntry, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	var file rulesYAMLFile
	if err := v.Unmarshal(&file); err != nil {
		return nil, err
	}
	return file.Rules, nil
}

// resolveYAMLFiles 解析路径为 YAML 文件列表（支持单文件和目录）
func resolveYAMLFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("路径不存在: %s", path)
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	var files []string
	yamlFiles, _ := filepath.Glob(filepath.Join(path, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(path, "*.yml"))
	files = append(files, yamlFiles...)
	files = append(files, ymlFiles...)

	if len(files) == 0 {
		return nil, fmt.Errorf("目录 %s 中无 YAML 文件", path)
	}
	return files, nil
}
