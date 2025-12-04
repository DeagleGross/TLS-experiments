# Use .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/nightly/sdk:10.0-preview AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY SslStreamConsole.csproj .
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

## UNCOMMENT TO USE A PATCHED SYSTEM.NET.SECURITY.DLL
# ---------------------------------------------------
## Copy patched System.Net.Security.dll and replace in runtime
#COPY --from=build /src/patched/System.Net.Security.dll /tmp/System.Net.Security.dll
#
## Replace the DLL in the .NET runtime directory (framework DLLs must be replaced there)
#RUN RUNTIME_DIR=$(find /usr/share/dotnet/shared/Microsoft.NETCore.App -maxdepth 1 -type d -name "10.0.*" | head -n 1) && \
    #echo "=== Replacing System.Net.Security.dll in: $RUNTIME_DIR ===" && \
    #echo "Original DLL:" && ls -lh "$RUNTIME_DIR/System.Net.Security.dll" && \
    #cp /tmp/System.Net.Security.dll "$RUNTIME_DIR/System.Net.Security.dll" && \
    #echo "Patched DLL:" && ls -lh "$RUNTIME_DIR/System.Net.Security.dll"

# Expose port
EXPOSE 5001

# Run the application
ENTRYPOINT ["dotnet", "SslStreamConsole.dll"]
