FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o lnky

# Use a small image for the final container
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl unzip groff less

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/lnky .

# Use PORT environment variable from AppRunner
EXPOSE ${PORT:-8080}

# Run the application
CMD ["./lnky"]