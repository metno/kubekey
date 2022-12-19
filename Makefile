kubekey: kubekey.go
	go mod download
	CGO_ENABLED=0 go build kubekey.go
