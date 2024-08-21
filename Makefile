VERSION = 0.1.$(shell date +%Y%m%d.%H%M)
FLAGS := "-s -w -X main.version=${VERSION} -buildid="


build:
	CGO_ENABLED=0 go build -ldflags=${FLAGS} -trimpath -buildvcs=false -o pkcs .
	objcopy --remove-section .go.buildinfo pkcs
