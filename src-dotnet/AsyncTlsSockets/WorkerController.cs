using Serilog;
using System.Threading.Channels;

namespace AsyncTlsSockets;

internal class WorkerController
{
    private readonly Channel<ConnectionContext> _acceptQueue;

    private int _port;
    private string _certPath;
    private string _keyPath;
    private int _workerCount;

    public WorkerController(int port, string certPath, string keyPath, int workerCount)
    {
        _port = port;
        _certPath = certPath;
        _keyPath = keyPath;
        _workerCount = workerCount;

        // We use Unbounded because we want the workers to dump ready 
        // connections as fast as they can without being blocked by 
        // slow application logic.
        var options = new UnboundedChannelOptions
        {
            // Set to true if ONLY your Program.cs loop calls AcceptAsync.
            // Set to false if you have multiple threads calling AcceptAsync.
            SingleReader = true,

            // MUST be false because all your TlsWorkers will be 
            // calling TryWrite() at the same time.
            SingleWriter = false,

            // RunContinuationsAsynchronously is critical for performance.
            // It ensures that when a worker writes to the channel, the 
            // "await" code in Program.cs doesn't run on the Worker's CPU core.
            AllowSynchronousContinuations = false
        };

        _acceptQueue = Channel.CreateUnbounded<ConnectionContext>(options);
    }

    public void StartWorkers()
    {
        for (int i = 0; i < _workerCount; i++)
        {
            var worker = new TlsWorker(i, _port, _certPath, _keyPath, _acceptQueue);

            Log.Information("Starting worker {WorkerId} on port {Port}", i, _port);
            worker.Start();
            Log.Information("Started worker {WorkerId} on port {Port}", i, _port);
        }
    }

    internal async Task<ConnectionContext> AcceptAsync(CancellationToken cancellationToken = default)
    {
        // This asynchronously waits for the Writer to call TryWrite/WriteAsync
        return await _acceptQueue.Reader.ReadAsync(cancellationToken);
    }
}
