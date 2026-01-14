namespace AsyncTlsSockets;

internal class WorkerController
{
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
    }

    public void StartWorkers()
    {
        for (int i = 0; i < _workerCount; i++)
        {
            var worker = new TlsWorker(i, _port, _certPath, _keyPath);
            worker.Start();
        }
    }
}
