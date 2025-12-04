namespace BioSslDedicatedThreadPool.Ssl;

/// <summary>
/// Result of a single handshake step iteration.
/// </summary>
public enum HandshakeState
{
    /// <summary>
    /// Handshake needs another iteration (SSL_ERROR_WANT_READ/WANT_WRITE).
    /// Re-queue the work item for another pass.
    /// </summary>
    NeedsMoreData,

    /// <summary>
    /// Handshake completed successfully.
    /// </summary>
    Complete,

    /// <summary>
    /// Handshake failed due to SSL error.
    /// </summary>
    Failed
}
