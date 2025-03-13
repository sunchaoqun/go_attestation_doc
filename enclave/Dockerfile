# 第一阶段：构建 Go 应用
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 安装 git 和其他必要的构建工具
RUN apk add --no-cache git

# 复制源代码
COPY main.go ./

# 初始化 Go 模块
RUN go mod init aws-enclave-attestation
RUN go get github.com/mdlayher/vsock && \
    go get github.com/spf13/cobra

# 检查语法错误
RUN go vet ./...

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o main main.go

# 第二阶段：创建运行镜像
FROM amazonlinux:2

# 安装基本工具
RUN yum install -y shadow-utils util-linux && yum clean all

WORKDIR /app
COPY --from=builder /app/main /app/main
COPY nsm-cli /app/nsm-cli

# 确保可执行文件有执行权限
RUN chmod +x /app/main /app/nsm-cli

# 添加 nsm-cli 到 PATH
ENV PATH="/app:${PATH}"

# 设置容器启动命令
ENTRYPOINT ["/app/main"] 