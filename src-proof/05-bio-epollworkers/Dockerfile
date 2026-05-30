FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Build tools and OpenSSL dev (for libbio_native.so)
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build native library first
COPY src/native/ ./native/
WORKDIR /src/native
RUN make

# Sanity check — native .so must exist
RUN ls -la /src/native/ && test -f /src/native/libbio_native.so

# Copy C# project files and restore
WORKDIR /src
COPY src/*.csproj ./
RUN dotnet restore

# Copy the rest of the C# project (excluding native, already copied)
COPY src/ ./
# Re-restore in case the project was modified by COPY (it wasn't, but cheap)
# Then publish.
RUN dotnet publish -c Release -o /app/publish

# Final runtime image
FROM mcr.microsoft.com/dotnet/runtime:10.0

RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring in the BIO-driven native lib next to the binary
COPY --from=build /src/native/libbio_native.so ./

# .NET app
COPY --from=build /app/publish ./

EXPOSE 5008

ENV CURVE=p384
ENV PORT=5008
ENV WORKERS=4

CMD ["sh", "-c", "dotnet BioEpollWorkers.dll ${PORT} ${WORKERS} --curve ${CURVE}"]
