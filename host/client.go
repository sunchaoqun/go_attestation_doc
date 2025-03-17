package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/mdlayher/vsock"
)

// 命令行参数结构 - 与 enclave 端匹配
type CommandArgs struct {
	UserData  string `json:"user_data"`
	PublicKey string `json:"public_key,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// 响应结构 - 与 enclave 端匹配
type Response struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
	Document     string `json:"document,omitempty"`
}

// 保存证明文档到文件
func saveAttestationDoc(document string, filename string) error {
	// 尝试解码 base64 编码的文档
	docBytes, err := base64.StdEncoding.DecodeString(document)
	if err != nil {
		// 如果解码失败，直接保存原始内容
		docBytes = []byte(document)
	}

	// 写入文件
	if err := os.WriteFile(filename, docBytes, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

func main() {
	// 定义命令行参数
	cidFlag := flag.Uint("cid", 16, "Enclave 的 CID")
	portFlag := flag.Uint("port", 5000, "vsock 端口")
	userDataFlag := flag.String("userdata", "", "用户数据")
	publicKeyFlag := flag.String("public-key", "", "公钥文件路径")
	nonceFlag := flag.String("nonce", "", "随机数")
	outputFlag := flag.String("output", "attestation_doc.bin", "输出文件路径")
	flag.Parse()

	// 检查 CID
	cid := *cidFlag
	if cid == 0 {
		log.Fatalf("必须指定 Enclave 的 CID")
	}

	// 连接到 Enclave - 使用 mdlayher/vsock 库
	conn, err := vsock.Dial(uint32(cid), uint32(*portFlag), nil)
	if err != nil {
		log.Fatalf("连接到 Enclave 失败: %v", err)
	}
	defer conn.Close()

	log.Printf("已连接到 Enclave (CID: %d)\n", cid)

	// 读取公钥文件（如果提供）
	var publicKeyContent string
	if *publicKeyFlag != "" {
		pkData, err := os.ReadFile(*publicKeyFlag)
		if err != nil {
			log.Fatalf("读取公钥文件失败: %v", err)
		}
		
		// 处理 PEM 格式的公钥
		pemContent := string(pkData)
		if strings.Contains(pemContent, "-----BEGIN PUBLIC KEY-----") {
			// 提取 PEM 中的 Base64 编码部分并解码为 DER 格式
			pemBlock, _ := pem.Decode(pkData)
			if pemBlock == nil {
				log.Fatalf("解析 PEM 格式公钥失败")
			}
			
			// 重新编码为 Base64 以便传输
			publicKeyContent = base64.StdEncoding.EncodeToString(pemBlock.Bytes)
		} else {
			// 如果不是 PEM 格式，假设是 DER 格式，直接进行 Base64 编码
			publicKeyContent = base64.StdEncoding.EncodeToString(pkData)
		}
	}

	// 准备参数
	args := CommandArgs{
		UserData:  *userDataFlag,
		PublicKey: publicKeyContent,
		Nonce:     *nonceFlag,
	}

	// 序列化参数
	argsJSON, err := json.Marshal(args)
	if err != nil {
		log.Fatalf("序列化参数失败: %v", err)
	}

	// 发送参数
	if _, err := conn.Write(argsJSON); err != nil {
		log.Fatalf("发送参数失败: %v", err)
	}

	log.Println("已发送参数，等待响应...")

	// 读取响应
	buffer := make([]byte, 65536) // 64KB 缓冲区
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		log.Fatalf("读取响应失败: %v", err)
	}

	// 解析响应
	var response Response
	if err := json.Unmarshal(buffer[:n], &response); err != nil {
		log.Fatalf("解析响应失败: %v", err)
	}

	// 处理响应
	if !response.Success {
		log.Fatalf("Enclave 返回错误: %s", response.ErrorMessage)
	}

	log.Println("成功接收到证明文档")

	// 保存证明文档
	if *outputFlag != "" {
		if err := saveAttestationDoc(response.Document, *outputFlag); err != nil {
			log.Printf("保存证明文档失败: %v\n", err)
		} else {
			log.Printf("证明文档已保存到 %s\n", *outputFlag)
		}
	}

	// 打印证明文档摘要
	fmt.Println("\n证明文档已接收")
	if len(response.Document) > 100 {
		fmt.Printf("文档大小: %d 字节, 前100字节: %s...\n", len(response.Document), response.Document[:100])
	} else {
		fmt.Printf("文档大小: %d 字节, 内容: %s\n", len(response.Document), response.Document)
	}
}
