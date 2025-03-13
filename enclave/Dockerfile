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

# 创建 nsm-cli 脚本
RUN echo '#!/bin/bash\n\
if [ "$1" = "describe-attestation-doc" ]; then\n\
  # 获取 nonce 参数\n\
  NONCE="default-nonce"\n\
  for ((i=1; i<=$#; i++)); do\n\
    if [ "${!i}" = "--nonce" ] && [ $((i+1)) -le $# ]; then\n\
      NONCE="${!((i+1))}"\n\
      break\n\
    fi\n\
  done\n\
  \n\
  # 尝试读取 NSM 设备\n\
  if [ -e /dev/nsm ]; then\n\
    dd if=/dev/nsm of=/dev/null bs=1 count=1 2>/dev/null || echo "警告: 无法读取 /dev/nsm" >&2\n\
  else\n\
    echo "警告: /dev/nsm 设备不存在" >&2\n\
  fi\n\
  \n\
  # 创建模拟的证明文档\n\
  DOC_TEXT="这是一个模拟的证明文档，nonce: $NONCE"\n\
  DOC_BASE64=$(echo -n "$DOC_TEXT" | base64)\n\
  \n\
  # 输出 JSON 格式的响应\n\
  echo "{\"attestation_doc\":\"$DOC_BASE64\"}"\n\
else\n\
  echo "用法: nsm-cli describe-attestation-doc [--json] [--nonce VALUE]" >&2\n\
  exit 1\n\
fi\n' > /usr/bin/nsm-cli

# 设置执行权限
RUN chmod +x /usr/bin/nsm-cli

WORKDIR /app

# 从构建器阶段复制二进制文件
COPY --from=builder /app/attestation-generator /app/

# 确保可执行文件有执行权限
RUN chmod +x /app/attestation-generator

# 设置容器启动命令
ENTRYPOINT ["/app/attestation-generator", "--server"] 