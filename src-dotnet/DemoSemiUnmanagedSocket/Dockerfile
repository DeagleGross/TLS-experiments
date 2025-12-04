FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Install build tools and OpenSSL dev
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy and build native library first
COPY native/ ./native/
WORKDIR /src/native
RUN make

# Verify native library was built
RUN ls -la /src/native/ && test -f /src/native/libdemo_native.so

# Copy C# project files
WORKDIR /src
COPY *.csproj ./
RUN dotnet restore

# Copy everything else
COPY . ./

# Build .NET application
RUN dotnet publish -c Release -o /app/publish

# Final runtime image
FROM mcr.microsoft.com/dotnet/runtime:10.0

# Install OpenSSL runtime
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy native library from build stage
COPY --from=build /src/native/libdemo_native.so ./

# Copy .NET application from build stage
COPY --from=build /app/publish ./

EXPOSE 5007

ENTRYPOINT ["dotnet", "DemoSemiUnmanagedSocket.dll"]
