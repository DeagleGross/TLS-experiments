using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket.Ssl.Requests;

/// <summary>
/// Represents a pending handshake request.
/// </summary>
internal sealed class HandshakeRequest
{
    public Socket ClientSocket { get; }
    public IntPtr Ssl { get; set; }
    public int ClientFd { get; }
    public TaskCompletionSource<HandshakeResult> Completion { get; }
    public int WorkerId { get; set; } = -1;

    public HandshakeRequest(Socket clientSocket)
    {
        ClientSocket = clientSocket;
        ClientFd = (int)clientSocket.Handle;
        Completion = new TaskCompletionSource<HandshakeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}