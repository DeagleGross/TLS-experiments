# Use .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/nightly/sdk:10.0-preview AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY AsyncSslConsole.csproj .
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

# Certificates will be mounted via docker-compose volume at /app/certs
# No need to COPY them during build

# Expose port
EXPOSE 5001

# Run the application
ENTRYPOINT ["dotnet", "AsyncSslConsole.dll"]
