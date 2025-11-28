# Use .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/nightly/sdk:10.0-preview AS build
WORKDIR /src

# Install build tools for native library
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project file and restore dependencies
COPY PureUnmanagedSockets.csproj .
RUN dotnet restore

# Copy source code
COPY . .

# Build native library first
WORKDIR /src/native
RUN make clean && make

# Build .NET application
WORKDIR /src
RUN dotnet build -c Release -o /app/build

# Copy native library to build output
RUN cp /src/native/libopenssl_native.so /app/build/

# Publish the application
RUN dotnet publish -c Release -o /app/publish

# Copy native library to publish output
RUN cp /src/native/libopenssl_native.so /app/publish/

# Use .NET 10 runtime for running
FROM mcr.microsoft.com/dotnet/nightly/runtime:10.0-preview AS runtime

# Install OpenSSL runtime libraries
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy published app
COPY --from=build /app/publish .

# Make sure native library is findable
ENV LD_LIBRARY_PATH=/app:$LD_LIBRARY_PATH

# Expose port (changed to 5005)
EXPOSE 5005

# Run the application
ENTRYPOINT ["dotnet", "PureUnmanagedSockets.dll"]

