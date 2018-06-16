FROM golang:1.10.3-alpine as build

RUN apk add --no-cache git openssh ca-certificates
RUN wget -O - https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
ADD . /go/src/github.com/thatsmrtalbot/k8s-vault-csr
WORKDIR /go/src/github.com/thatsmrtalbot/k8s-vault-csr
RUN dep ensure -vendor-only -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o /bin/k8s-vault-csr ./cmd/k8s-vault-csr

FROM scratch

COPY --from=build /bin/k8s-vault-csr /bin/k8s-vault-csr
ENTRYPOINT [ "/bin/k8s-vault-csr" ]