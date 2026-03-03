.PHONY: build build-arm64 docker-arm64 test vet clean

build:
	go build -o awgconfbot .

build-arm64:
	GOOS=linux GOARCH=arm64 go build -o awgconfbot-arm64 .

docker-arm64:
	docker build --platform linux/arm64 -t awgconfbot:arm64 .

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f awgconfbot awgconfbot-arm64
