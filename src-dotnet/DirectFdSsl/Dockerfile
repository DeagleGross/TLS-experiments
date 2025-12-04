# Direct fd-based SSL Server (No BIOs)
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY DirectFdSsl.csproj .
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release -o /app/publish

# Runtime
FROM mcr.microsoft.com/dotnet/runtime:9.0 AS runtime

# Install OpenSSL 3
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/publish .

EXPOSE 6002

ENTRYPOINT ["dotnet", "DirectFdSsl.dll"]
CMD ["6002", "certs/server-p384.crt", "certs/server-p384.key"]
