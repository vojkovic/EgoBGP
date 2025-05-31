FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-w -s" -o egobgp

FROM scratch

COPY --from=builder /app/egobgp /egobgp

ENTRYPOINT ["/egobgp"] 