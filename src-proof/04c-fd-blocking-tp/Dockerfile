FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src
COPY src/*.csproj ./
RUN dotnet restore

COPY src/ ./
RUN dotnet publish -c Release -o /app/publish

# Final runtime image
FROM mcr.microsoft.com/dotnet/runtime:10.0

RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/publish ./

EXPOSE 5011

ENV CURVE=p384
ENV PORT=5011
ENV MIN_THREADS=256

CMD ["sh", "-c", "dotnet FdBlockingTp.dll ${PORT} --curve ${CURVE}"]
