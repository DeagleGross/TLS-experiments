using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FdBlockingTp.Ssl;

namespace FdBlockingTp;

/// <summary>
/// Experiment 04c — <c>SSL_set_fd</c> on a BLOCKING socket, dispatched via
/// .NET <see cref="ThreadPool"/> (i.e. <c>Task.Run</c>).
///
/// Pair-difference with experiment 04 (DemoSemiUnmanagedSocket):
///   - 04  = SSL_set_fd + nonblocking socket + 4 dedicated epoll worker threads
///   - 04c = SSL_set_fd + blocking socket + 1 dedicated accept thread + ThreadPool dispatch
///
/// Pair-difference with experiment 04d (siblings):
///   - 04d = same blocking SSL_set_fd path but dispatched onto a FIXED pool of
///           dedicated OS threads. 04c isolates "what does the .NET ThreadPool
///           cost us on blocking SSL?" on top of 04d's "what does epoll cost
///           us on top of blocking?" answer.
///
/// Everything else (TLS config, response body, cert, cpuset, ulimits) is held
/// constant with 04 / 04d so any RPS / CPU delta is attributable to the
/// dispatch model.
///
/// Why <c>ThreadPool.SetMinThreads</c> is pre-tuned:
///   The .NET ThreadPool hill-climbs at ~1 thread/sec after exhausting
///   <c>Environment.ProcessorCount</c>. With wrk -c500 each blocking
///   <c>SSL_do_handshake</c> holds a ThreadPool thread for ~5–10ms; defaults
///   would starve the pool for the entire 10s benchmark window and the
///   measured RPS would be dominated by the hill-climb cost, not by the
///   "blocking + ThreadPool" pattern itself. We pre-size to remove that
///   confounder. The 04 vs 04c delta is then attributable to the dispatch
///   model, not to thread-injection latency.
/// </summary>
internal static class Program
{
    private const int DefaultPort = 5011;
    private const int DefaultMinThreads = 256;

    private static long _accepted;
    private static long _completed;
    private static long _failed;

    private static int Main(string[] args)
    {
        Console.WriteLine("=== TLS Server: SSL_set_fd + BLOCKING socket + ThreadPool dispatch (experiment 04c) ===");
        Console.WriteLine();

        int port = GetPort(args) ?? DefaultPort;
        int minThreads = GetMinThreads() ?? DefaultMinThreads;
        string? curve = GetCurve(args);

        var (certPath, keyPath) = FindCertificatePaths(curve);
        if (certPath is null || keyPath is null)
        {
            Console.Error.WriteLine("ERROR: No certificate files found in any expected location.");
            return 1;
        }

        // Pre-size the ThreadPool BEFORE the listener starts so the very first
        // wave of wrk connections doesn't trigger hill-climbing.
        ThreadPool.SetMinThreads(minThreads, minThreads);
        ThreadPool.GetMinThreads(out int actualWorker, out int actualIo);
        Console.WriteLine($"[cfg] ThreadPool min threads = worker {actualWorker} / io {actualIo}");
        Console.WriteLine($"[cfg] Environment.ProcessorCount = {Environment.ProcessorCount}");
        Console.WriteLine($"[cfg] Port = {port}");
        Console.WriteLine($"[cfg] Cert = {certPath}");
        Console.WriteLine();

        using var sslContext = new SslContext(certPath, keyPath);

        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Bind(new IPEndPoint(IPAddress.Any, port));
        listener.Listen(512);
        listener.Blocking = true;

        Console.WriteLine($"✓ Listening on port {port}");
        Console.WriteLine("Press Ctrl+C to stop.");
        Console.WriteLine();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            // Unblock the Accept() call so the loop can observe cancellation.
            try
            {
                listener.Close();
            }
            catch
            {
            }
        };

        var stopwatch = Stopwatch.StartNew();
        var statsTask = Task.Run(() => StatsLoop(stopwatch, cts.Token));

        try
        {
            while (!cts.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = listener.Accept();
                }
                catch (SocketException)
                {
                    // Likely from listener.Close() during shutdown.
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                Interlocked.Increment(ref _accepted);

                // Fire-and-forget onto the ThreadPool — the canonical
                // "naive blocking-IO in .NET" pattern.
                _ = Task.Run(() => HandleConnection(client, sslContext));
            }
        }
        finally
        {
            try
            {
                listener.Close();
            }
            catch
            {
            }
            try
            {
                statsTask.Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
            }
        }

        stopwatch.Stop();
        PrintFinalStats(stopwatch.Elapsed);
        return 0;
    }

    private static void HandleConnection(Socket client, SslContext ctx)
    {
        SslConnection? conn = null;
        try
        {
            client.NoDelay = true;
            client.Blocking = true;

            conn = new SslConnection(ctx, client);
            conn.Handshake();
            conn.WriteHttpResponse();

            Interlocked.Increment(ref _completed);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _failed);
            // Errors are expected at high churn (wrk closes hard, etc.). Keep
            // the bench output clean by not logging per-connection failures.
            _ = ex;
        }
        finally
        {
            conn?.Dispose();
            try
            {
                client.Close();
            }
            catch
            {
            }
        }
    }

    private static async Task StatsLoop(Stopwatch sw, CancellationToken ct)
    {
        long lastCompleted = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            long completed = Interlocked.Read(ref _completed);
            long failed = Interlocked.Read(ref _failed);
            long accepted = Interlocked.Read(ref _accepted);
            long delta = completed - lastCompleted;
            lastCompleted = completed;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] accepted={accepted} completed={completed} (+{delta}/s) failed={failed}");
        }
    }

    private static void PrintFinalStats(TimeSpan elapsed)
    {
        long completed = Interlocked.Read(ref _completed);
        long failed = Interlocked.Read(ref _failed);
        long accepted = Interlocked.Read(ref _accepted);
        Console.WriteLine();
        Console.WriteLine("=== Final Statistics ===");
        Console.WriteLine($"Runtime:   {elapsed.TotalSeconds:F2}s");
        Console.WriteLine($"Accepted:  {accepted}");
        Console.WriteLine($"Completed: {completed}");
        Console.WriteLine($"Failed:    {failed}");
        if (elapsed.TotalSeconds > 0)
        {
            Console.WriteLine($"Avg RPS:   {completed / elapsed.TotalSeconds:F2}");
        }
        Console.WriteLine("========================");
    }

    private static (string? certPath, string? keyPath) FindCertificatePaths(string? curve)
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),
            Path.Combine("..", "..", "certs"),
            Path.Combine("..", "..", "..", "..", "certs"),
        };

        if (curve is not null)
        {
            foreach (var basePath in basePaths)
            {
                var c = Path.Combine(basePath, $"server-{curve}.crt");
                var k = Path.Combine(basePath, $"server-{curve}.key");
                if (File.Exists(c) && File.Exists(k))
                {
                    return (c, k);
                }
            }
            Console.Error.WriteLine($"WARNING: Certificate for curve '{curve}' not found; falling back to default.");
        }

        foreach (var basePath in basePaths)
        {
            var c = Path.Combine(basePath, "server.crt");
            var k = Path.Combine(basePath, "server.key");
            if (File.Exists(c) && File.Exists(k))
            {
                return (c, k);
            }

            c = Path.Combine(basePath, "server-p384.crt");
            k = Path.Combine(basePath, "server-p384.key");
            if (File.Exists(c) && File.Exists(k))
            {
                return (c, k);
            }
        }

        return (null, null);
    }

    private static int? GetPort(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p1))
            {
                return p1;
            }
            if (int.TryParse(args[i], out var p2) && p2 > 1000 && args[i] is not "p256" and not "p384")
            {
                return p2;
            }
        }
        return null;
    }

    private static int? GetMinThreads()
    {
        var raw = Environment.GetEnvironmentVariable("MIN_THREADS");
        return int.TryParse(raw, out var v) && v > 0 ? v : null;
    }

    private static string? GetCurve(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--curve" && i + 1 < args.Length)
            {
                var curve = args[i + 1].ToLowerInvariant();
                if (curve is "p256" or "p384")
                {
                    return curve;
                }
            }
            if (args[i] is "p256" or "p384")
            {
                return args[i].ToLowerInvariant();
            }
        }
        return null;
    }
}
