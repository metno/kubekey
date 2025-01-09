.PHONY: all clean update

all: kubekey

clean:
	rm -f kubekey

kubekey: kubekey.go
	go mod download
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' kubekey.go

update:
	go get -u ./...
	go mod tidy
