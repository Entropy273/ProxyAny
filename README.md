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
docker run -p 10230:10230 proxyany
```
