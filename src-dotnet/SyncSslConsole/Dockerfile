# Use .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/nightly/sdk:10.0-preview AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY SyncSslConsole.csproj .
RUN dotnet restore

# Copy source code and build
COPY . .
RUN dotnet build -c Release -o /app/build

# Publish the application
RUN dotnet publish -c Release -o /app/publish

# Use .NET 10 runtime for running
FROM mcr.microsoft.com/dotnet/nightly/runtime:10.0-preview AS runtime
WORKDIR /app

# Copy published app
COPY --from=build /app/publish .

# Expose port
EXPOSE 5002

# Environment variable for certificate curve (p256, p384)
ENV CURVE=p384

# Run the application with curve from environment variable
CMD ["sh", "-c", "dotnet SyncSslConsole.dll --curve ${CURVE}"]
