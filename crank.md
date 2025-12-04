In order to test the crank behavior for patched kestrel use this doc.


This runs a TLS-handshake performance benchmark against kestrel
```
crank --config https://github.com/aspnet/Benchmarks/blob/main/scenarios/tls.benchmarks.yml?raw=true --config https://raw.githubusercontent.com/aspnet/Benchmarks/main/build/azure.profile.yml --scenario tls-handshakes-kestrel --profile aspnet-perf-lin --profile short
```

```
crank --config https://github.com/aspnet/Benchmarks/blob/main/scenarios/tls.benchmarks.yml?raw=true --config https://raw.githubusercontent.com/aspnet/Benchmarks/main/build/azure.profile.yml --scenario tls-handshakes-kestrel --application.options.outputFiles "D:\code\aspnetcore\artifacts\bin\Microsoft.AspNetCore.Server.Kestrel.Core\Release\net10.0\*.dll" --application.options.outputFiles "D:\code\aspnetcore\artifacts\bin\Microsoft.AspNetCore.Server.Kestrel\Release\net10.0\*.dll" --profile aspnet-perf-lin --profile short
```