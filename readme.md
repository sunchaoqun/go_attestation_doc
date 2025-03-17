sudo yum install golang

go mod tidy

go build -o attestation-client ./host/client.go

nitro-cli terminate-enclave --all

# 构建 Docker 镜像
docker build -t aws-enclave-attestation:latest -f ./enclave/Dockerfile ./enclave

# 导出 Docker 镜像为 EIF 文件
nitro-cli build-enclave --docker-uri aws-enclave-attestation:latest --output-file enclave.eif

# 运行 Enclave
nitro-cli run-enclave --eif-path enclave.eif --enclave-cid 16 --memory 1024 --cpu-count 2 --debug-mode --attach-console

nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

export INSTANCE_ID=i-02f8fc047b1c66083

aws ec2 describe-instances --instance-ids $INSTANCE_ID --region us-west-2 --query "Reservations[0].Instances[0].EnclaveOptions"


# 生成私钥
openssl ecparam -name secp384r1 -genkey -noout -out private.pem

# 从私钥提取公钥
openssl ec -in private.pem -pubout -out public.pem


./attestation-client \
  --cid 16 \
  --port 5000 \
  --userdata "这是自定义用户数据" \
  --public-key public.pem \
  --nonce "123456" \
  --output "my-attestation.bin"

./attestation-client --cid 16 --output "my-attestation.bin"


pip install cbor2

python3 parse_attestation.py my-attestation.bin

