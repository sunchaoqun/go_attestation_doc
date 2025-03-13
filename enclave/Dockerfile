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
FROM amazonlinux:2

# 安装基本工具
RUN yum install -y shadow-utils util-linux && \
    yum clean all

# 创建 nsm-cli 脚本（使用多行 RUN 命令避免转义问题）
RUN echo '#!/bin/bash' > /usr/bin/nsm-cli && \
    echo 'if [ "$1" = "describe-attestation-doc" ]; then' >> /usr/bin/nsm-cli && \
    echo '  # 获取 nonce 参数' >> /usr/bin/nsm-cli && \
    echo '  NONCE="default-nonce"' >> /usr/bin/nsm-cli && \
    echo '  for ((i=1; i<=$#; i++)); do' >> /usr/bin/nsm-cli && \
    echo '    if [ "${!i}" = "--nonce" ] && [ $((i+1)) -le $# ]; then' >> /usr/bin/nsm-cli && \
    echo '      NONCE="${!((i+1))}"' >> /usr/bin/nsm-cli && \
    echo '      break' >> /usr/bin/nsm-cli && \
    echo '    fi' >> /usr/bin/nsm-cli && \
    echo '  done' >> /usr/bin/nsm-cli && \
    echo '' >> /usr/bin/nsm-cli && \
    echo '  # 创建模拟的证明文档' >> /usr/bin/nsm-cli && \
    echo '  DOC_TEXT="这是一个模拟的证明文档，nonce: $NONCE"' >> /usr/bin/nsm-cli && \
    echo '  DOC_BASE64=$(echo -n "$DOC_TEXT" | base64)' >> /usr/bin/nsm-cli && \
    echo '' >> /usr/bin/nsm-cli && \
    echo '  # 输出 JSON 格式的响应' >> /usr/bin/nsm-cli && \
    echo '  echo "{\"attestation_doc\":\"$DOC_BASE64\"}"' >> /usr/bin/nsm-cli && \
    echo 'else' >> /usr/bin/nsm-cli && \
    echo '  echo "用法: nsm-cli describe-attestation-doc [--json] [--nonce VALUE]" >&2' >> /usr/bin/nsm-cli && \
    echo '  exit 1' >> /usr/bin/nsm-cli && \
    echo 'fi' >> /usr/bin/nsm-cli && \
    chmod +x /usr/bin/nsm-cli

WORKDIR /app

# 从构建器阶段复制二进制文件
COPY --from=builder /app/attestation-generator /app/

# 确保可执行文件有执行权限
RUN chmod +x /app/attestation-generator

# 设置容器启动命令
ENTRYPOINT ["/app/attestation-generator", "--server"] 