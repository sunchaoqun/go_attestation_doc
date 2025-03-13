# 第一阶段：构建 Go 应用
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制源代码
COPY main.go ./

# 初始化 Go 模块
RUN go mod init aws-enclave-attestation

# 添加 vsock 依赖
RUN go get github.com/mdlayher/vsock

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o attestation-generator main.go

# 确保可执行文件有正确的权限
RUN chmod +x attestation-generator

# 第二阶段：创建最小运行镜像
FROM alpine:latest

# 安装必要的工具和依赖
RUN apk --no-cache add ca-certificates bash procps curl

# 安装 nsm-cli 工具
RUN curl -Lo /usr/bin/nsm-cli https://github.com/aws/aws-nitro-enclaves-cli/raw/main/nsm-tools/nsm-cli && \
    chmod +x /usr/bin/nsm-cli

WORKDIR /app

# 从构建器阶段复制二进制文件
COPY --from=builder /app/attestation-generator /app/

# 确保可执行文件有执行权限
RUN chmod +x /app/attestation-generator

# 设置容器启动命令
ENTRYPOINT ["/app/attestation-generator", "--server"] 