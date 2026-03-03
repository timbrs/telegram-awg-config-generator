FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o awgconfbot .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/awgconfbot /usr/local/bin/awgconfbot
WORKDIR /app
CMD ["awgconfbot"]
