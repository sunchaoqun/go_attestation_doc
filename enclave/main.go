package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"github.com/mdlayher/vsock"
	"github.com/spf13/cobra"
)

const (
	// vsock 端口
	vsockPort = 5000
)

// 命令行参数结构
type CommandArgs struct {
	UserData string `json:"user_data"`
}

// 响应结构
type Response struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
	Document     string `json:"document,omitempty"`
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

	// 使用 nsm-cli 生成证明文档
	var cmd *exec.Cmd
	if args.UserData == "" {
		cmd = exec.Command("nsm-cli", "attest")
	} else {
		cmd = exec.Command("nsm-cli", "attest", "--user-data", args.UserData)
	}

	output, err := cmd.Output()
	if err != nil {
		log.Printf("执行 nsm-cli attest 失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("执行 nsm-cli attest 失败: %v", err))
		return
	}

	// 准备响应
	response := Response{
		Success:  true,
		Document: string(output),
	}

	// 序列化响应
	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("序列化响应失败: %v\n", err)
		sendErrorResponse(conn, fmt.Sprintf("序列化响应失败: %v", err))
		return
	}

	// 发送响应
	if _, err := conn.Write(responseJSON); err != nil {
		log.Printf("发送响应失败: %v\n", err)
		return
	}

	log.Println("已成功发送证明文档")
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
	log.Println("启动 vsock 服务器...")

	listener, err := vsock.Listen(uint32(vsockPort), nil)
	if err != nil {
		log.Fatalf("无法创建 vsock 监听器: %v", err)
	}
	defer listener.Close()

	log.Printf("vsock 服务器已启动，监听端口 %d\n", vsockPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v\n", err)
			continue
		}

		log.Printf("接收到新连接: %v\n", conn.RemoteAddr())
		go handleClient(conn)
	}
}

// CLI 命令实现
func describeNSM() {
	fmt.Println("NSM 描述功能在当前版本的 nsm-cli 中不可用")
}

func getRandom() {
	cmd := exec.Command("nsm-cli", "get-random", "--length", "256")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("执行 nsm-cli get-random 失败: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

func describePCR(index uint16) {
	cmd := exec.Command("nsm-cli", "describe-pcr", "--index", fmt.Sprintf("%d", index))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("执行 nsm-cli describe-pcr 失败: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

func generateAttestation(userData string) {
	var cmd *exec.Cmd
	if userData == "" {
		cmd = exec.Command("nsm-cli", "attest")
	} else {
		cmd = exec.Command("nsm-cli", "attest", "--user-data", userData)
	}
	
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("执行 nsm-cli attest 失败: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

// 设置 CLI 命令
func setupCLI() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "nsm-cli",
		Short: "Nitro Security Module CLI",
		Long:  "Command line interface for interacting with the Nitro Security Module",
	}

	// Add describe-nsm subcommand
	describeNSMCmd := &cobra.Command{
		Use:   "describe-nsm",
		Short: "Returns capabilities and version of the connected NitroSecureModule",
		Run: func(cmd *cobra.Command, args []string) {
			describeNSM()
		},
	}
	rootCmd.AddCommand(describeNSMCmd)

	// Add get-random subcommand
	getRandomCmd := &cobra.Command{
		Use:   "get-random",
		Short: "Returns 256 bytes of pseudo-random numbers (entropy)",
		Run: func(cmd *cobra.Command, args []string) {
			getRandom()
		},
	}
	rootCmd.AddCommand(getRandomCmd)

	// Add describe-pcr subcommand
	describePCRCmd := &cobra.Command{
		Use:   "describe-pcr",
		Short: "Read data from PlatformConfigurationRegister at some index",
		Run: func(cmd *cobra.Command, args []string) {
			index, _ := cmd.Flags().GetInt("index")
			describePCR(uint16(index))
		},
	}
	describePCRCmd.Flags().IntP("index", "i", 0, "The PCR index (0..n)")
	describePCRCmd.MarkFlagRequired("index")
	rootCmd.AddCommand(describePCRCmd)

	// Add attestation subcommand
	attestationCmd := &cobra.Command{
		Use:   "attestation",
		Short: "Create an AttestationDoc and sign it with its private key to ensure authenticity",
		Run: func(cmd *cobra.Command, args []string) {
			userData, _ := cmd.Flags().GetString("userdata")
			generateAttestation(userData)
		},
	}
	attestationCmd.Flags().StringP("userdata", "d", "", "Additional user data")
	rootCmd.AddCommand(attestationCmd)

	return rootCmd
}

func main() {
	// 检查是否在 CLI 模式运行
	if len(os.Args) > 1 && (os.Args[1] == "describe-nsm" || 
							os.Args[1] == "get-random" || 
							os.Args[1] == "describe-pcr" || 
							os.Args[1] == "attestation") {
		rootCmd := setupCLI()
		if err := rootCmd.Execute(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	// 否则启动 vsock 服务器
	startVsockServer()
}
