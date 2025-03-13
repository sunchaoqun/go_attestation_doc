package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"github.com/mdlayher/vsock"
)

const (
	// NSM 设备路径
	nsmDevicePath = "/dev/nsm"

	// NSM 命令
	nsmCmdGetAttestationDoc = 0x20

	// 最大消息大小
	maxMessageSize = 16384

	// vsock 端口
	vsockPort = 5000
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

// NSM 请求头
type nsmRequestHeader struct {
	MessageType uint32
	MessageLen  uint32
}

// NSM 响应头
type nsmResponseHeader struct {
	MessageType uint32
	MessageLen  uint32
}

// 证明文档请求
type attestationDocRequest struct {
	Version uint32
	Nonce   [64]byte
}

// 证明文档响应
type attestationDocResponse struct {
	Version      uint32
	Status       uint32
	DocumentLen  uint32
	DocumentData [maxMessageSize]byte
}

// 检查是否在 Enclave 环境中运行
func isRunningInEnclave() bool {
	_, err := os.Stat(nsmDevicePath)
	return err == nil
}

// 方法1: 使用 nsm-cli 工具获取签名的证明文档
func getSignedAttestationDocWithCLI(nonce string) (string, error) {
	// 检查 nsm-cli 是否可用
	_, err := exec.LookPath("nsm-cli")
	if err != nil {
		log.Println("nsm-cli 工具不可用，尝试直接与 NSM 设备交互...")
		return getSignedAttestationDocDirect(nonce)
	}

	// 在 Nitro Enclave 中，我们使用 nsm-cli 工具来获取证明文档
	var cmd *exec.Cmd
	if nonce == "" {
		cmd = exec.Command("nsm-cli", "describe-attestation-doc", "--json")
	} else {
		cmd = exec.Command("nsm-cli", "describe-attestation-doc", "--json", "--nonce", nonce)
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("执行 nsm-cli 失败: %v", err)
	}

	// 解析 JSON 输出
	var result struct {
		AttestationDoc string `json:"attestation_doc"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("解析 nsm-cli 输出失败: %v", err)
	}

	return result.AttestationDoc, nil
}

// 方法2: 直接与 NSM 设备交互获取签名的证明文档
func getSignedAttestationDocDirect(nonceStr string) (string, error) {
	// 打开 NSM 设备
	nsmDevice, err := os.OpenFile(nsmDevicePath, os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("无法打开 NSM 设备: %v", err)
	}
	defer nsmDevice.Close()

	// 准备请求
	var request attestationDocRequest
	request.Version = 1

	// 如果提供了 nonce，将其复制到请求中
	if nonceStr != "" {
		copy(request.Nonce[:], []byte(nonceStr))
	}

	// 序列化请求头
	reqHeader := nsmRequestHeader{
		MessageType: nsmCmdGetAttestationDoc,
		MessageLen:  uint32(unsafe.Sizeof(request)),
	}

	// 创建请求缓冲区
	reqBuf := new(bytes.Buffer)
	if err := binary.Write(reqBuf, binary.LittleEndian, reqHeader); err != nil {
		return "", fmt.Errorf("序列化请求头失败: %v", err)
	}
	if err := binary.Write(reqBuf, binary.LittleEndian, request); err != nil {
		return "", fmt.Errorf("序列化请求体失败: %v", err)
	}

	// 发送请求
	if _, err := nsmDevice.Write(reqBuf.Bytes()); err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}

	// 读取响应头
	var respHeader nsmResponseHeader
	if err := binary.Read(nsmDevice, binary.LittleEndian, &respHeader); err != nil {
		return "", fmt.Errorf("读取响应头失败: %v", err)
	}

	// 读取响应体
	var response attestationDocResponse
	if err := binary.Read(nsmDevice, binary.LittleEndian, &response); err != nil {
		return "", fmt.Errorf("读取响应体失败: %v", err)
	}

	// 检查状态
	if response.Status != 0 {
		return "", fmt.Errorf("NSM 返回错误状态: %d", response.Status)
	}

	// 提取证明文档
	docBytes := response.DocumentData[:response.DocumentLen]

	// 编码为 base64
	docBase64 := base64.StdEncoding.EncodeToString(docBytes)

	return docBase64, nil
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

// 解析证明文档
func parseAttestationDoc(document string) (map[string]interface{}, error) {
	// 解码 base64 编码的文档
	docBytes, err := base64.StdEncoding.DecodeString(document)
	if err != nil {
		return nil, fmt.Errorf("解码证明文档失败: %v", err)
	}

	// 解析 JSON
	var result map[string]interface{}
	if err := json.Unmarshal(docBytes, &result); err != nil {
		return nil, fmt.Errorf("解析证明文档失败: %v", err)
	}

	return result, nil
}

// 处理客户端连接
func handleClient(conn net.Conn) {
	defer conn.Close()

	log.Println("接收到新的客户端连接")

	// 读取客户端发送的参数
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("读取客户端数据失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("读取客户端数据失败: %v", err))
		return
	}

	// 解析参数
	var args CommandArgs
	if err := json.Unmarshal(buffer[:n], &args); err != nil {
		log.Printf("解析参数失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("解析参数失败: %v", err))
		return
	}

	log.Printf("收到参数: UseCLI=%v, Nonce=%s, OutputFile=%s, Parse=%v\n",
		args.UseCLI, args.Nonce, args.OutputFile, args.Parse)

	// 获取证明文档
	var document string
	if args.UseCLI {
		log.Println("使用 nsm-cli 工具获取证明文档...")
		document, err = getSignedAttestationDocWithCLI(args.Nonce)
	} else {
		log.Println("直接与 NSM 设备交互获取证明文档...")
		document, err = getSignedAttestationDocDirect(args.Nonce)
	}

	if err != nil {
		log.Printf("获取证明文档失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("获取证明文档失败: %v", err))
		return
	}

	log.Println("成功获取签名证明文档")

	// 如果指定了输出文件，保存证明文档
	if args.OutputFile != "" {
		if err := saveAttestationDoc(document, args.OutputFile); err != nil {
			log.Printf("保存证明文档失败: %v\n", err)
			// 继续执行，不返回错误
		} else {
			log.Printf("证明文档已保存到 %s\n", args.OutputFile)
		}
	}

	// 准备响应
	response := Response{
		Success:  true,
		Document: document,
	}

	// 如果需要解析文档
	if args.Parse {
		parsedDoc, err := parseAttestationDoc(document)
		if err != nil {
			log.Printf("解析证明文档失败: %v\n", err)
			// 继续执行，不返回错误
		} else {
			response.ParsedDoc = parsedDoc
		}
	}

	// 发送响应
	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("序列化响应失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("序列化响应失败: %v", err))
		return
	}

	if _, err := conn.Write(responseJSON); err != nil {
		log.Printf("发送响应失败: %v\n", err)
		return
	}

	log.Println("成功发送响应")
}

// 发送错误响应
func sendErrorResponse(conn net.Conn, errorMessage string) {
	response := Response{
		Success:      false,
		ErrorMessage: errorMessage,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("序列化错误响应失败: %v\n", err)
		return
	}

	if _, err := conn.Write(responseJSON); err != nil {
		log.Printf("发送错误响应失败: %v\n", err)
		return
	}
}

// 启动 vsock 服务器
func startVsockServer() {
	log.Println("尝试启动 vsock 服务器...")

	// 检查 vsock 设备
	if _, err := os.Stat("/dev/vsock"); err != nil {
		log.Printf("警告: 未找到 /dev/vsock 设备: %v", err)
	} else {
		log.Println("找到 /dev/vsock 设备")
	}

	// 使用 mdlayher/vsock 库
	// 正确的 Listen 函数调用需要两个参数：端口号和配置
	listener, err := vsock.Listen(uint32(vsockPort), nil)
	if err != nil {
		log.Fatalf("无法创建 vsock 监听器: %v", err)
	}
	defer listener.Close()

	log.Printf("vsock 服务器已启动，监听端口 %d\n", vsockPort)

	// 接受连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v\n", err)
			continue
		}

		log.Printf("接收到新连接: %v\n", conn.RemoteAddr())

		// 为每个连接创建一个 goroutine
		go handleClient(conn)
	}
}

// 获取 CID
func getCID() (uint32, error) {
	// 在 Nitro Enclave 中，CID 通常是 16（本地 CID）
	// 但我们尝试从多个来源获取它

	// 1. 尝试从 /proc/self/status 获取 CID
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Cpid:") || strings.HasPrefix(line, "VmCID:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					cid, err := strconv.ParseUint(parts[1], 10, 32)
					if err == nil {
						log.Printf("从 /proc/self/status 获取到 CID: %d", cid)
						return uint32(cid), nil
					}
				}
			}
		}
	}

	// 2. 尝试从 vsock 获取本地 CID
	// 在 Nitro Enclave 中，本地 CID 通常是 16
	localCID := uint32(16)
	log.Printf("使用默认本地 CID: %d", localCID)
	return localCID, nil
}

func main() {
	// 定义命令行参数
	serverMode := flag.Bool("server", true, "以服务器模式运行（在 Enclave 中）")
	clientMode := flag.Bool("client", false, "以客户端模式运行（在宿主机中）")
	cidFlag := flag.Uint("cid", 0, "Enclave 的 CID（客户端模式下使用）")
	useCLIFlag := flag.Bool("cli", false, "使用 nsm-cli 工具获取证明文档")
	nonceFlag := flag.String("nonce", "random-nonce-value", "用于证明文档的 nonce 值")
	outputFlag := flag.String("output", "attestation_doc.bin", "输出文件路径")
	parseFlag := flag.Bool("parse", false, "解析并打印证明文档内容")
	flag.Parse()

	// 客户端模式（在宿主机上运行）
	if *clientMode {
		// 检查 CID
		cid := *cidFlag
		if cid == 0 {
			log.Fatalf("客户端模式下必须指定 Enclave 的 CID")
		}

		// 连接到 Enclave
		conn, err := net.Dial("vsock", fmt.Sprintf("vsock://%d:%d", cid, vsockPort))
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

		return
	}

	// 服务器模式（在 Enclave 中运行）
	if *serverMode {
		// 检查是否在 Enclave 环境中运行
		if !isRunningInEnclave() {
			log.Println("警告: 未在 Nitro Enclave 环境中运行")
			log.Println("此程序需要在 AWS Nitro Enclave 环境中运行")
			// 在非 Enclave 环境中继续运行，用于测试
		} else {
			log.Println("在 Nitro Enclave 环境中运行")
		}

		// 获取并打印 CID
		cid, err := getCID()
		if err != nil {
			log.Printf("获取 CID 失败: %v\n", err)
		} else {
			log.Printf("Enclave CID: %d\n", cid)
		}

		// 启动 vsock 服务器
		startVsockServer()
		return
	}

	// 如果既不是客户端模式也不是服务器模式，直接运行（兼容旧版本）
	// 检查是否在 Enclave 环境中运行
	if !isRunningInEnclave() {
		log.Println("警告: 未在 Nitro Enclave 环境中运行")
		log.Println("此程序需要在 AWS Nitro Enclave 环境中运行")
		os.Exit(1)
	}

	log.Println("在 Nitro Enclave 环境中运行")

	// 使用命令行参数中的 nonce
	nonce := *nonceFlag
	log.Printf("正在获取带有 nonce '%s' 的签名证明文档...\n", nonce)

	// 根据命令行参数选择使用哪种方法获取证明文档
	var document string
	var err error

	if *useCLIFlag {
		log.Println("使用 nsm-cli 工具获取证明文档...")
		document, err = getSignedAttestationDocWithCLI(nonce)
	} else {
		log.Println("直接与 NSM 设备交互获取证明文档...")
		document, err = getSignedAttestationDocDirect(nonce)
	}

	if err != nil {
		log.Printf("获取证明文档失败: %v\n", err)
		os.Exit(1)
	}

	log.Println("成功获取签名证明文档")

	// 保存证明文档到文件
	outputFile := *outputFlag
	if err := saveAttestationDoc(document, outputFile); err != nil {
		log.Printf("保存证明文档失败: %v\n", err)
		os.Exit(1)
	}

	log.Printf("证明文档已保存到 %s\n", outputFile)

	// 打印 base64 编码的证明文档
	fmt.Println("\n签名证明文档 (base64 编码):")
	fmt.Println(document)

	// 根据命令行参数决定是否解析并打印证明文档内容
	if *parseFlag {
		parsedDoc, err := parseAttestationDoc(document)
		if err != nil {
			log.Printf("解析证明文档失败: %v\n", err)
		} else {
			fmt.Println("\n证明文档内容:")
			jsonBytes, _ := json.MarshalIndent(parsedDoc, "", "  ")
			fmt.Println(string(jsonBytes))
		}
	}
}
