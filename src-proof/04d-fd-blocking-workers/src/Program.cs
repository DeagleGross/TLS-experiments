using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FdBlockingWorkers.Ssl;

namespace FdBlockingWorkers;

/// <summary>
/// Experiment 04d — <c>SSL_set_fd</c> on a BLOCKING socket, dispatched onto a
/// FIXED pool of dedicated OS threads (NOT the .NET ThreadPool).
///
/// Pair-difference with experiment 04 (DemoSemiUnmanagedSocket):
///   - 04  = SSL_set_fd + nonblocking + 4 epoll workers driving the state machine
///   - 04d = SSL_set_fd + blocking    + N fixed worker threads, each blocked in
///           the kernel inside its own SSL_do_handshake
///
/// This is the CLEAN epoll-vs-no-epoll comparison because the thread count and
/// thread lifetime model are held constant (a fixed pool of dedicated OS
/// threads in both cases — just no epoll dispatcher in 04d). 04 and 04d differ
/// only in:
///   - 04 uses nonblocking sockets + epoll_wait readiness events;
///   - 04d uses blocking sockets + kernel-side parking inside read()/write().
///
/// Pair-difference with experiment 04c (sibling):
///   - 04c puts work on the .NET ThreadPool (variable-size, hill-climbing
///     governor). 04d holds the threading model constant against 04, so the
///     04 vs 04d delta is "what does epoll itself buy us" and the 04c vs 04d
///     delta is "what does ThreadPool overhead add on top".
///
/// Tunable: WORKERS env (default 64). Worker count is OS-thread count, NOT
/// CPU-bound; with wrk -c500 and ~10ms blocking handshakes, ~50-100 workers
/// is the minimum to saturate the 4 cores without leaving requests queued
/// behind blocked threads.
/// </summary>
internal static class Program
{
    private const int DefaultPort = 5012;
    private const int DefaultWorkers = 64;
    private const int QueueCapacity = 2048;

    private static long _accepted;
    private static long _completed;
    private static long _failed;
    private static long _queueDropped;

    private static int Main(string[] args)
    {
        Console.WriteLine("=== TLS Server: SSL_set_fd + BLOCKING socket + fixed OS-thread worker pool (experiment 04d) ===");
        Console.WriteLine();

        int port = GetPort(args) ?? DefaultPort;
        int workers = GetWorkers() ?? DefaultWorkers;
        string? curve = GetCurve(args);

        var (certPath, keyPath) = FindCertificatePaths(curve);
        if (certPath is null || keyPath is null)
        {
            Console.Error.WriteLine("ERROR: No certificate files found in any expected location.");
            return 1;
        }

        Console.WriteLine($"[cfg] Worker threads = {workers} (fixed, dedicated OS threads — NOT the .NET ThreadPool)");
        Console.WriteLine($"[cfg] Environment.ProcessorCount = {Environment.ProcessorCount}");
        Console.WriteLine($"[cfg] Queue capacity = {QueueCapacity}");
        Console.WriteLine($"[cfg] Port = {port}");
        Console.WriteLine($"[cfg] Cert = {certPath}");
        Console.WriteLine();

        using var sslContext = new SslContext(certPath, keyPath);
        using var queue = new BlockingCollection<Socket>(new ConcurrentQueue<Socket>(), QueueCapacity);

        var workerThreads = new Thread[workers];
        for (int i = 0; i < workers; i++)
        {
            int idx = i;
            var t = new Thread(() => WorkerLoop(idx, queue, sslContext))
            {
                IsBackground = true,
                Name = $"tls-worker-{idx:000}",
            };
            t.Start();
            workerThreads[i] = t;
        }
        Console.WriteLine($"[init] Started {workers} dedicated worker threads.");

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
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                Interlocked.Increment(ref _accepted);

                if (!queue.TryAdd(client, millisecondsTimeout: 0))
                {
                    // Queue full — kill the connection rather than blocking the
                    // accept thread. With WORKERS sized correctly this should
                    // never happen during the bench.
                    Interlocked.Increment(ref _queueDropped);
                    try
                    {
                        client.Close();
                    }
                    catch
                    {
                    }
                }
            }
        }
        finally
        {
            queue.CompleteAdding();
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
            // Best-effort drain so we don't leak sockets on shutdown.
            foreach (var t in workerThreads)
            {
                t.Join(TimeSpan.FromSeconds(2));
            }
        }

        stopwatch.Stop();
        PrintFinalStats(stopwatch.Elapsed);
        return 0;
    }

    private static void WorkerLoop(int workerIndex, BlockingCollection<Socket> queue, SslContext ctx)
    {
        try
        {
            foreach (var client in queue.GetConsumingEnumerable())
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
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[worker {workerIndex}] FATAL: {ex.Message}");
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
            long dropped = Interlocked.Read(ref _queueDropped);
            long delta = completed - lastCompleted;
            lastCompleted = completed;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] accepted={accepted} completed={completed} (+{delta}/s) failed={failed} qDrop={dropped}");
        }
    }

    private static void PrintFinalStats(TimeSpan elapsed)
    {
        long completed = Interlocked.Read(ref _completed);
        long failed = Interlocked.Read(ref _failed);
        long accepted = Interlocked.Read(ref _accepted);
        long dropped = Interlocked.Read(ref _queueDropped);
        Console.WriteLine();
        Console.WriteLine("=== Final Statistics ===");
        Console.WriteLine($"Runtime:      {elapsed.TotalSeconds:F2}s");
        Console.WriteLine($"Accepted:     {accepted}");
        Console.WriteLine($"Completed:    {completed}");
        Console.WriteLine($"Failed:       {failed}");
        Console.WriteLine($"Queue drops:  {dropped}");
        if (elapsed.TotalSeconds > 0)
        {
            Console.WriteLine($"Avg RPS:      {completed / elapsed.TotalSeconds:F2}");
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

    private static int? GetWorkers()
    {
        var raw = Environment.GetEnvironmentVariable("WORKERS");
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
