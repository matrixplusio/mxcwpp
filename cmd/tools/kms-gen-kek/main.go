// Package main 生成 mxsec KMS 主密钥 (KEK), 一次性初次部署用。
//
// 用法:
//
//	go run ./cmd/tools/kms-gen-kek
//
// 输出 32 字节随机数据的 base64 编码。
// 把输出写入 systemd EnvironmentFile:
//
//	# /etc/mxsec/kms.env
//	MXSEC_KMS_KEK_V1=<base64>
package main

import (
	"fmt"
	"os"

	"github.com/imkerbos/mxsec-platform/internal/server/common/kms"
)

func main() {
	kek, err := kms.GenerateKEK()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate KEK: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(kek)
}
