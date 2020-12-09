COMMITID=$(shell git rev-parse HEAD)
RELEASE="./target/release"

buildversion:
	printf "package main\n\nconst(\ncommitID=\"$(COMMITID)\"\n)\n" > version.go

build: buildversion
	mkdir -p $(RELEASE)
	GOOS=windows go build -ldflags "-s -w" -o $(RELEASE)/evtmon.exe ./...