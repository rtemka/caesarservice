# syntax=docker/dockerfile:1

FROM golang:1.18-buster as build

WORKDIR /go/src/github.com/rtemka/cypherservice

COPY go.* .
COPY ./pkg ./pkg
COPY ./cmd ./cmd

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o ./cmd/service/service ./cmd/service/service.go

FROM scratch

WORKDIR /app

COPY --from=build go/src/github.com/rtemka/cypherservice/cmd/service/ .

EXPOSE 8080

CMD ["./service"]