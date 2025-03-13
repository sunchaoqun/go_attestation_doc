# 第一阶段：构建 Go 应用
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 复制 Go 模块文件
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# 复制源代码
COPY *.go ./

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o attestation-generator .

# 第二阶段：创建最小运行镜像
FROM alpine:latest

# 安装必要的工具（如果需要 nsm-cli）
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# 从构建器阶段复制二进制文件
COPY --from=builder /app/attestation-generator .

# 设置容器启动命令
ENTRYPOINT ["./attestation-generator", "--server"] 