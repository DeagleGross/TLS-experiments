using System;
using System.Collections.Concurrent;
using Serilog;

namespace AsyncTlsSockets;

public static class ConnectionRegistry
{
    private static long _nextId = 1;
    private static readonly ConcurrentDictionary<long, ConnectionContext> _connections = new();

    public static long Register(ConnectionContext context)
    {
        long id = Interlocked.Increment(ref _nextId);
        context._id = id; // to later be able to unregister itself
        _connections[id] = context;

        Log.Debug("[ConnectionRegistry] Registering new connection ID {Id}", id);
        return id;
    }

    public static ConnectionContext? Get(long id) => _connections.TryGetValue(id, out var ctx) ? ctx : null;

    public static void Unregister(long id)
    {
        Log.Debug("[ConnectionRegistry] Unregistering connection ID {Id}", id);
        _connections.TryRemove(id, out _);  
    } 
}
