FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o proxy .

FROM scratch
COPY --from=build /app/proxy /proxy
EXPOSE 8080
ENTRYPOINT ["/proxy"]
