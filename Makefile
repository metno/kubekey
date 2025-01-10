.PHONY: all clean update

all: kubekey-darwin-amd64 kubekey-linux-amd64 kubekey-windows-amd64.exe

clean:
	rm -f kubekey-*-amd64*

kubekey-%-amd64: kubekey.go
	go mod download
	GOOS=$(patsubst kubekey-%-amd64,%,$@) GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o $@ kubekey.go

kubekey-%-amd64.exe: kubekey-%-amd64
	mv $^ $@

update:
	go get -u ./...
	go mod tidy
