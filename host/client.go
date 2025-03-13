package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/mdlayher/vsock"
)

// 命令行参数结构
type CommandArgs struct {
	UseCLI     bool   `json:"use_cli"`
	Nonce      string `json:"nonce"`
	OutputFile string `json:"output_file"`
	Parse      bool   `json:"parse"`
}

// 响应结构
type Response struct {
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Document     string                 `json:"document,omitempty"`
	ParsedDoc    map[string]interface{} `json:"parsed_doc,omitempty"`
}

// 保存证明文档到文件
func saveAttestationDoc(document string, filename string) error {
	// 解码 base64 编码的文档
	docBytes, err := base64.StdEncoding.DecodeString(document)
	if err != nil {
		return fmt.Errorf("解码证明文档失败: %v", err)
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
	useCLIFlag := flag.Bool("cli", false, "使用 nsm-cli 工具获取证明文档")
	nonceFlag := flag.String("nonce", "random-nonce-value", "用于证明文档的 nonce 值")
	outputFlag := flag.String("output", "attestation_doc.bin", "输出文件路径")
	parseFlag := flag.Bool("parse", false, "解析并打印证明文档内容")
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

	// 准备参数
	args := CommandArgs{
		UseCLI:     *useCLIFlag,
		Nonce:      *nonceFlag,
		OutputFile: *outputFlag,
		Parse:      *parseFlag,
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

	// 打印证明文档
	fmt.Println("\n签名证明文档 (base64 编码):")
	fmt.Println(response.Document)

	// 如果有解析的文档，打印它
	if response.ParsedDoc != nil {
		fmt.Println("\n证明文档内容:")
		jsonBytes, _ := json.MarshalIndent(response.ParsedDoc, "", "  ")
		fmt.Println(string(jsonBytes))
	}
}
