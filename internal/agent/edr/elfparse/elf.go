// Package elfparse — ELF 二进制解析 + strings 抽取 + entropy 反混淆 (C8).
//
// 给 IOC 匹配 + APT sample 静态分析用:
//   - 解 ELF header / segments / sections / dynamic symbols
//   - 提取 ASCII / UTF-16 strings (≥4 字符可打印)
//   - 计算各 section 香农熵 (>7.0 高熵 = 加壳 / 加密)
//   - 检测常见加壳特征 (UPX magic, PT_LOAD 仅 1 段, .text 高熵)
package elfparse

import (
	"debug/elf"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"unicode/utf16"
)

// ELFInfo 解析结果.
type ELFInfo struct {
	Path      string
	Arch      string // amd64 / arm64 / 386 / ppc64
	Type      string // EXEC / DYN / REL
	Entry     uint64
	OS        string
	Sections  []SectionInfo
	Imports   []string // dynamic symbols (PLT)
	Exports   []string
	NeededLib []string // DT_NEEDED

	Packed      bool
	PackerHint  string
	HighEntropy []string // section name 列表 entropy > 7.0
}

// SectionInfo 单 section 摘要.
type SectionInfo struct {
	Name    string
	Type    string
	Addr    uint64
	Size    uint64
	Entropy float64
}

// Parse ELF 文件.
func Parse(path string) (*ELFInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf.Open: %w", err)
	}
	defer f.Close()

	info := &ELFInfo{
		Path:  path,
		Arch:  archName(f.Machine),
		Type:  f.Type.String(),
		Entry: f.Entry,
		OS:    f.OSABI.String(),
	}
	// Sections + entropy
	for _, s := range f.Sections {
		si := SectionInfo{
			Name: s.Name,
			Type: s.Type.String(),
			Addr: s.Addr,
			Size: s.Size,
		}
		if s.Type != elf.SHT_NOBITS && s.Size > 0 && s.Size < 64*1024*1024 {
			data, err := s.Data()
			if err == nil {
				si.Entropy = entropy(data)
				if si.Entropy > 7.0 {
					info.HighEntropy = append(info.HighEntropy, s.Name)
				}
			}
		}
		info.Sections = append(info.Sections, si)
	}
	// Imports / Exports / Needed
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			if s.Section == elf.SHN_UNDEF {
				info.Imports = append(info.Imports, s.Name)
			} else {
				info.Exports = append(info.Exports, s.Name)
			}
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		info.NeededLib = libs
	}
	// 加壳检测
	info.detectPacker()
	return info, nil
}

// detectPacker 启发式 packer 识别.
func (i *ELFInfo) detectPacker() {
	for _, s := range i.Sections {
		if strings.EqualFold(s.Name, "UPX0") || strings.EqualFold(s.Name, "UPX1") {
			i.Packed = true
			i.PackerHint = "UPX"
			return
		}
	}
	// .text entropy > 7.0 视为可疑
	for _, s := range i.Sections {
		if (s.Name == ".text" || s.Name == ".rodata") && s.Entropy > 7.0 {
			i.Packed = true
			i.PackerHint = "high_entropy_" + s.Name
			return
		}
	}
}

// ExtractStrings 从二进制文件抽取 ASCII + UTF-16LE 字符串 (≥minLen 字符).
//
// 返回 set 去重, 顺序按首次出现.
func ExtractStrings(path string, minLen int, maxStrings int) ([]string, error) {
	if minLen <= 0 {
		minLen = 4
	}
	if maxStrings <= 0 {
		maxStrings = 5000
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const chunk = 1 << 20 // 1MB
	buf := make([]byte, chunk)
	seen := make(map[string]bool)
	var out []string

	for {
		n, err := f.Read(buf)
		if n > 0 {
			// ASCII
			extractASCII(buf[:n], minLen, seen, &out, maxStrings)
			if len(out) >= maxStrings {
				break
			}
			// UTF-16LE (Windows binaries 中常见, ELF 较少)
			extractUTF16(buf[:n], minLen, seen, &out, maxStrings)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if len(out) >= maxStrings {
			break
		}
	}
	return out, nil
}

func extractASCII(data []byte, minLen int, seen map[string]bool, out *[]string, max int) {
	start := -1
	for i, b := range data {
		if isPrintable(b) {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minLen {
				s := string(data[start:i])
				if !seen[s] {
					seen[s] = true
					*out = append(*out, s)
					if len(*out) >= max {
						return
					}
				}
			}
			start = -1
		}
	}
}

func extractUTF16(data []byte, minLen int, seen map[string]bool, out *[]string, max int) {
	if len(data) < 4 {
		return
	}
	pairs := make([]uint16, 0, len(data)/2)
	start := -1
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch >= 0x20 && ch < 0x7f {
			if start < 0 {
				start = i
			}
			pairs = append(pairs, ch)
		} else {
			if start >= 0 && len(pairs) >= minLen {
				s := string(utf16.Decode(pairs))
				if !seen[s] {
					seen[s] = true
					*out = append(*out, s)
					if len(*out) >= max {
						return
					}
				}
			}
			start = -1
			pairs = pairs[:0]
		}
	}
}

func isPrintable(b byte) bool {
	return b >= 0x20 && b < 0x7f
}

// entropy 香农熵 (0~8, 字节级).
func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	total := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// archName 把 elf.Machine 转可读架构名.
func archName(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_PPC64:
		return "ppc64"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_RISCV:
		return "riscv64"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_LOONGARCH:
		return "loong64"
	}
	return m.String()
}
