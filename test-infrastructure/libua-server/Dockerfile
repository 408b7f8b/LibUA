FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY NET-Core/LibUA/LibUA.csproj NET-Core/LibUA/
COPY NET-Core/TestServer/TestServer.csproj NET-Core/TestServer/
RUN dotnet restore NET-Core/TestServer/TestServer.csproj
COPY NET-Core/LibUA/ NET-Core/LibUA/
COPY NET-Core/TestServer/ NET-Core/TestServer/
RUN dotnet publish NET-Core/TestServer/TestServer.csproj -c Release -f net9.0 -o /app

FROM mcr.microsoft.com/dotnet/runtime:9.0
WORKDIR /app
COPY --from=build /app .
EXPOSE 7718
ENTRYPOINT ["dotnet", "TestServer.dll"]
