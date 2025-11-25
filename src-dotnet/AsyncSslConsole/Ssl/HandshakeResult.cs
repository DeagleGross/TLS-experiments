namespace AsyncSslConsole.Ssl;

/// <summary>
/// Represents the result of an SSL handshake operation.
/// </summary>
public enum HandshakeResult
{
    /// <summary>
    /// Handshake completed successfully.
    /// </summary>
    Complete,

    /// <summary>
    /// Socket needs to be readable before continuing.
    /// Corresponds to SSL_ERROR_WANT_READ.
    /// </summary>
    WantRead,

    /// <summary>
    /// Socket needs to be writable before continuing.
    /// Corresponds to SSL_ERROR_WANT_WRITE.
    /// </summary>
    WantWrite,

    /// <summary>
    /// Handshake failed with an error.
    /// </summary>
    Error
}
