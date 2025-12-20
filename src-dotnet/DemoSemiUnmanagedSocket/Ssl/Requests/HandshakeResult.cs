namespace DemoSemiUnmanagedSocket.Ssl.Requests;

/// <summary>
/// Result of a handshake operation.
/// </summary>
public enum HandshakeResult
{
    Success,
    Failed,
    Timeout
}