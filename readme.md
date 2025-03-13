go build -o attestation-client ./host/client.go


# 构建 Docker 镜像
docker build -t aws-enclave-attestation:latest -f ./enclave/Dockerfile ./enclave

# 导出 Docker 镜像为 EIF 文件
nitro-cli build-enclave --docker-uri aws-enclave-attestation:latest --output-file enclave.eif

# 运行 Enclave
nitro-cli run-enclave --eif-path enclave.eif --memory 512 --cpu-count 2 --debug-mode

# 获取 Enclave 的 CID
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')