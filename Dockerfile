FROM golang:1.10.3 as build

ARG DEP_VERSION=0.4.1

# install dep
RUN wget -O /usr/local/bin/dep https://github.com/golang/dep/releases/download/v${DEP_VERSION}/dep-linux-amd64 && \
    chmod +x /usr/local/bin/dep

# add code
ADD . /go/src/github.com/thatsmrtalbot/k8s-vault-csr
WORKDIR /go/src/github.com/thatsmrtalbot/k8s-vault-csr

# vendor and build
RUN make bin/linux_amd64/k8s-vault-csr USE_DOCKER=0 VENDOR_ONLY=1

# final container
FROM scratch
COPY --from=build /go/src/github.com/thatsmrtalbot/k8s-vault-csr/bin/linux_amd64/k8s-vault-csr /bin/k8s-vault-csr
ENTRYPOINT [ "/bin/k8s-vault-csr" ]