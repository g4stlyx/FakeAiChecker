# Use the official ASP.NET Core runtime as a parent image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

# Use the official SDK image to build the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["FakeAiChecker.csproj", "."]
RUN dotnet restore "FakeAiChecker.csproj"
COPY . .
WORKDIR "/src"
RUN dotnet build "FakeAiChecker.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "FakeAiChecker.csproj" -c Release -o /app/publish

# Final stage/image
FROM base AS final
WORKDIR /app

# Install security tools
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1001 appuser
RUN chown -R appuser:appuser /app
USER appuser

COPY --from=publish /app/publish .

# Create temp directory with restricted permissions
RUN mkdir -p /tmp/scan_temp && chmod 700 /tmp/scan_temp

ENTRYPOINT ["dotnet", "FakeAiChecker.dll"]
