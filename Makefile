.PHONY: all clean update

all: kubekey-darwin-amd64 kubekey-darwin-arm64 kubekey-linux-amd64 kubekey-windows-amd64.exe

clean:
	rm -f kubekey-*

kubekey-%-amd64: *.go
	go mod download
	GOOS=$(patsubst kubekey-%-amd64,%,$@) GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o $@ .

kubekey-%-arm64: *.go
	go mod download
	GOOS=$(patsubst kubekey-%-arm64,%,$@) GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o $@ .

kubekey-%-amd64.exe: kubekey-%-amd64
	mv $^ $@

update:
	go get -u ./...
	go mod tidy
