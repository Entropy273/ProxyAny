# ProxyAny
Proxy GitHub & HuggingFace & Docker & PyPi & ... with one port!

## Supported Sites
- [x] Github
- [x] HuggingFace
- [x] Docker
- [x] pypi

## Build
```shell
GOOS=linux GOARCH=amd64 go build -o ./bin/ProxyAny-linux-amd64 main.go
```

## Docker Build
```shell
docker build -t proxyany .
```

## Docker Run
```shell
docker run -d -p 10230:10230 --restart=unless-stopped --name ProxyAny proxyany
```

## Test Command
```shell
wget "https://mirr.top/github.com/pytorch/pytorch/releases/download/v2.5.0/pytorch-v2.5.0.tar.gz"
wget "https://mirr.top/huggingface.co/Qwen/Qwen3-235B-A22B-Instruct-2507/resolve/main/model-00001-of-00118.safetensors"
```