FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    liburing-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build native io_uring library
COPY native/ ./native/
WORKDIR /src/native
RUN make

RUN ls -la /src/native/ && test -f /src/native/liburing_native.so

# Restore .NET dependencies
WORKDIR /src
COPY *.csproj ./
RUN dotnet restore

# Build .NET app
COPY . ./
RUN dotnet publish -c Release -o /app/publish

# ── Runtime image ──────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/runtime:10.0

RUN apt-get update && apt-get install -y \
    libssl3 \
    liburing2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy native library
COPY --from=build /src/native/liburing_native.so ./

# Copy .NET publish output
COPY --from=build /app/publish ./

EXPOSE 5009

ENV CURVE=p384
ENV PORT=5009
ENV WORKERS=4

CMD ["sh", "-c", "dotnet UringTlsSockets.dll ${PORT} ${WORKERS} --curve ${CURVE}"]
