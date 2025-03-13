sudo yum install golang

go mod tidy

go build -o attestation-client ./host/client.go


# 构建 Docker 镜像
docker build -t aws-enclave-attestation:latest -f ./enclave/Dockerfile ./enclave

# 导出 Docker 镜像为 EIF 文件
nitro-cli build-enclave --docker-uri aws-enclave-attestation:latest --output-file enclave.eif

# 运行 Enclave
nitro-cli run-enclave --eif-path enclave.eif --enclave-cid 16 --memory 1024 --cpu-count 2 --debug-mode --attach-console

nitro-cli terminate-enclave --all

nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

export INSTANCE_ID=i-02f8fc047b1c66083

aws ec2 describe-instances --instance-ids $INSTANCE_ID --region us-west-2 --query "Reservations[0].Instances[0].EnclaveOptions"



./attestation-client --cid 16 --output "my-attestation.bin"


