# syntax=docker/dockerfile:1
# One image per service, built from a release tag by CI:
#   docker build --build-arg SERVICE=indexer --build-arg VERSION=services-v1.0.0 services
# Both base images are pinned by digest, so a tag always builds the same toolchain and runtime.

FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
ARG SERVICE
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN test -n "$SERVICE" && test -d "cmd/$SERVICE"
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X github.com/cyphras/cyphras-contracts/services/internal/service.Version=${VERSION}" \
  -o /out/service "./cmd/${SERVICE}"

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/service /service
USER 65532:65532
ENTRYPOINT ["/service"]
