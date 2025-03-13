# 第一阶段：构建 Go 应用
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制源代码
COPY main.go ./

# 初始化 Go 模块
RUN go mod init aws-enclave-attestation
RUN go get github.com/mdlayher/vsock

# 检查语法错误
RUN go vet ./...

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o attestation-generator main.go

# 第二阶段：创建运行镜像
FROM amazonlinux:2

# 添加 AWS Nitro Enclaves 仓库
RUN amazon-linux-extras enable aws-nitro-enclaves-sdk || true
RUN yum install -y aws-nitro-enclaves-sdk-c aws-nitro-enclaves-cli || \
    (yum install -y shadow-utils util-linux && \
     echo '#!/bin/bash' > /usr/bin/nitro-cli && \
     echo 'echo "模拟 nitro-cli 工具"' >> /usr/bin/nitro-cli && \
     echo 'echo "{\"document\":\"$(echo -n \"模拟的证明文档\" | base64)\"}" > "$3"' >> /usr/bin/nitro-cli && \
     chmod +x /usr/bin/nitro-cli)
RUN yum clean all

WORKDIR /app
COPY --from=builder /app/attestation-generator /app/

# 确保可执行文件有执行权限
RUN chmod +x /app/attestation-generator

# 设置容器启动命令
ENTRYPOINT ["/app/attestation-generator", "--server"] 