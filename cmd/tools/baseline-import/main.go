// Package main 将 Elkeid baseline yaml 转成 mxcwpp baseline JSON。
//
// 用法:
//
//	go run ./cmd/tools/baseline-import \
//	    -in  Elkeid/plugins/baseline/config/linux/1200.yaml \
//	    -out plugins/baseline/config/cis/centos.json \
//	    -policy-id LINUX_CIS_CENTOS \
//	    -policy-name "CentOS CIS + 等保 2.0 基线 (借鉴 Elkeid)" \
//	    -os centos
//
// 字段映射:
//
//	Elkeid                          mxcwpp
//	---------------                 ---------------------
//	check_id                        rule_id (Policy_xxxx 拼接)
//	title / title_cn                title (中英拼接)
//	description / description_cn    description
//	solution / solution_cn          fix.suggestion
//	security                        severity
//	type / type_cn                  category
//	check.rules[].type              CheckRule.Type
//	check.rules[].param             CheckRule.Param[0]
//	check.rules[].filter            CheckRule.Param[1] (file_line_check → file_line_expr)
//	check.rules[].result            CheckRule.Result
//
// type 重命名:
//
//	file_line_check → file_line_expr
//	command_check   → command_exec
//	file_permission → file_permission (保持)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type elkeidPolicy struct {
	BaselineID      int           `yaml:"baseline_id"`
	BaselineVersion string        `yaml:"baseline_version"`
	BaselineName    string        `yaml:"baseline_name"`
	BaselineNameEN  string        `yaml:"baseline_name_en"`
	System          []string      `yaml:"system"`
	CheckList       []elkeidCheck `yaml:"check_list"`
}

type elkeidCheck struct {
	CheckID       int             `yaml:"check_id"`
	Type          string          `yaml:"type"`
	Title         string          `yaml:"title"`
	Description   string          `yaml:"description"`
	Solution      string          `yaml:"solution"`
	Security      string          `yaml:"security"`
	TypeCN        string          `yaml:"type_cn"`
	TitleCN       string          `yaml:"title_cn"`
	DescriptionCN string          `yaml:"description_cn"`
	SolutionCN    string          `yaml:"solution_cn"`
	Check         elkeidCheckSpec `yaml:"check"`
}

type elkeidCheckSpec struct {
	Rules []elkeidRule `yaml:"rules"`
}

type elkeidRule struct {
	Type   string      `yaml:"type"`
	Param  interface{} `yaml:"param"` // 可能是 []string 或 string
	Filter string      `yaml:"filter"`
	Result string      `yaml:"result"`
}

type mxcwppPolicy struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	OSFamily    []string      `json:"os_family"`
	OSVersion   string        `json:"os_version,omitempty"`
	Enabled     bool          `json:"enabled"`
	Rules       []*mxcwppRule `json:"rules"`
}

type mxcwppRule struct {
	RuleID      string       `json:"rule_id"`
	Category    string       `json:"category"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Check       *mxcwppCheck `json:"check"`
	Fix         *mxcwppFix   `json:"fix,omitempty"`
}

type mxcwppCheck struct {
	Condition string             `json:"condition"`
	Rules     []*mxcwppCheckRule `json:"rules"`
}

type mxcwppCheckRule struct {
	Type   string   `json:"type"`
	Param  []string `json:"param"`
	Result string   `json:"result,omitempty"`
}

type mxcwppFix struct {
	Suggestion string `json:"suggestion"`
}

func main() {
	in := flag.String("in", "", "input Elkeid baseline yaml")
	out := flag.String("out", "", "output mxcwpp baseline JSON")
	policyID := flag.String("policy-id", "", "mxcwpp Policy.ID (e.g. LINUX_CIS_CENTOS)")
	policyName := flag.String("policy-name", "", "Policy.Name")
	osFamilies := flag.String("os", "", "comma-separated os_family override (defaults to yaml system)")
	flag.Parse()
	if *in == "" || *out == "" || *policyID == "" {
		flag.Usage()
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}
	var src elkeidPolicy
	if err := yaml.Unmarshal(raw, &src); err != nil {
		fmt.Fprintf(os.Stderr, "parse yaml: %v\n", err)
		os.Exit(1)
	}
	dst := convert(src, *policyID, *policyName, *osFamilies)
	enc, err := json.MarshalIndent(dst, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, enc, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK  in=%s  out=%s  rules=%d\n", *in, *out, len(dst.Rules))
}

func convert(src elkeidPolicy, policyID, policyName, osFamiliesOverride string) *mxcwppPolicy {
	osFamily := src.System
	if osFamiliesOverride != "" {
		osFamily = strings.Split(osFamiliesOverride, ",")
		for i := range osFamily {
			osFamily[i] = strings.TrimSpace(osFamily[i])
		}
	}
	desc := src.BaselineName
	if src.BaselineNameEN != "" {
		desc = src.BaselineName + " / " + src.BaselineNameEN
	}
	name := policyName
	if name == "" {
		name = src.BaselineName
	}
	dst := &mxcwppPolicy{
		ID:          policyID,
		Name:        name,
		Version:     src.BaselineVersion,
		Description: desc + "\n借鉴 Elkeid baseline (Apache 2.0, https://github.com/bytedance/Elkeid).",
		OSFamily:    osFamily,
		Enabled:     true,
		Rules:       make([]*mxcwppRule, 0, len(src.CheckList)),
	}
	for _, c := range src.CheckList {
		r := convertCheck(policyID, c)
		if r != nil {
			dst.Rules = append(dst.Rules, r)
		}
	}
	return dst
}

func convertCheck(policyID string, c elkeidCheck) *mxcwppRule {
	title := c.Title
	if c.TitleCN != "" {
		title = c.TitleCN
		if c.Title != "" {
			title = c.TitleCN + " / " + c.Title
		}
	}
	desc := c.Description
	if c.DescriptionCN != "" {
		desc = c.DescriptionCN
	}
	sol := c.Solution
	if c.SolutionCN != "" {
		sol = c.SolutionCN
	}
	category := c.Type
	if c.TypeCN != "" {
		category = c.TypeCN
	}
	severity := strings.ToLower(c.Security)
	if severity == "" {
		severity = "medium"
	}
	rules := make([]*mxcwppCheckRule, 0, len(c.Check.Rules))
	for _, r := range c.Check.Rules {
		mr := mapRule(r)
		if mr != nil {
			rules = append(rules, mr)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	out := &mxcwppRule{
		RuleID:      fmt.Sprintf("%s_%04d", policyID, c.CheckID),
		Category:    category,
		Title:       title,
		Description: desc,
		Severity:    severity,
		Check: &mxcwppCheck{
			Condition: "all",
			Rules:     rules,
		},
	}
	if sol != "" {
		out.Fix = &mxcwppFix{Suggestion: sol}
	}
	return out
}

func mapRule(r elkeidRule) *mxcwppCheckRule {
	params := flattenParam(r.Param)
	switch r.Type {
	case "file_line_check":
		// param[0]=file, filter=regex, result=expr → file_line_expr
		out := &mxcwppCheckRule{
			Type:   "file_line_expr",
			Param:  []string{},
			Result: r.Result,
		}
		if len(params) > 0 {
			out.Param = append(out.Param, params[0])
		}
		if r.Filter != "" {
			out.Param = append(out.Param, r.Filter)
		}
		return out
	case "command_check":
		// param[0]=cmd, param[1]=expected output regex → command_exec
		return &mxcwppCheckRule{
			Type:   "command_exec",
			Param:  params,
			Result: r.Result,
		}
	case "file_permission":
		return &mxcwppCheckRule{
			Type:   "file_permission",
			Param:  params,
			Result: r.Result,
		}
	}
	// 未识别 type 透传
	return &mxcwppCheckRule{
		Type:   r.Type,
		Param:  params,
		Result: r.Result,
	}
}

// flattenParam 把 yaml 多形态 param 统一成 []string。
func flattenParam(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprintf("%v", x))
		}
		return out
	case []string:
		return t
	}
	return []string{fmt.Sprintf("%v", v)}
}
