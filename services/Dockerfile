# syntax=docker/dockerfile:1
# One image per service, built from a release tag by CI:
#   docker build --build-arg SERVICE=indexer --build-arg VERSION=services-v1.0.0 services
# Both base images are pinned by digest, so a tag always builds the same toolchain and runtime.

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
ARG SERVICE
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN test -n "$SERVICE" && test -d "cmd/$SERVICE"
# The version reaches the linker flags only in the form of a release tag, or as dev.
RUN printf '%s\n' "$VERSION" | grep -Eqx 'services-v[0-9]+\.[0-9]+\.[0-9]+|dev'
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X github.com/cyphras/cyphras-contracts/services/internal/service.Version=${VERSION}" \
  -o /out/service "./cmd/${SERVICE}"

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/service /service
USER 65532:65532
ENTRYPOINT ["/service"]
