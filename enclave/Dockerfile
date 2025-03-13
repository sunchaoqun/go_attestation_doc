# 第一阶段：构建 Go 应用
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制源代码
COPY main.go ./

# 初始化 Go 模块
RUN go mod init aws-enclave-attestation

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o attestation-generator main.go

# 确保可执行文件有正确的权限
RUN chmod +x attestation-generator

# 第二阶段：创建最小运行镜像
FROM alpine:latest

# 安装必要的工具和调试工具
RUN apk --no-cache add ca-certificates bash procps

WORKDIR /app

# 从构建器阶段复制二进制文件
COPY --from=builder /app/attestation-generator /app/

# 创建启动脚本以便调试
RUN echo '#!/bin/sh\n\
echo "Starting application..."\n\
echo "Current directory: $(pwd)"\n\
echo "Directory contents:"\n\
ls -la /app\n\
echo "Running application:"\n\
/app/attestation-generator --server\n' > /app/start.sh && chmod +x /app/start.sh

# 设置容器启动命令
ENTRYPOINT ["/app/start.sh"] 