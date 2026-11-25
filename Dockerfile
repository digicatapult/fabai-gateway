FROM golang:1.27.4-trixie@sha256:0f82c58710c405cc012da2fbd2b04bde9ced20392a89f66062822d711d7d6b4b AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/ ./cmd/fabai-gateway ./cmd/fabai-collateral

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS collateral
COPY --from=build /out/fabai-collateral /fabai-collateral
USER nonroot:nonroot
EXPOSE 8085
ENTRYPOINT ["/fabai-collateral"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS gateway
COPY --from=build /out/fabai-gateway /fabai-gateway
USER nonroot:nonroot
EXPOSE 443
ENTRYPOINT ["/fabai-gateway"]
