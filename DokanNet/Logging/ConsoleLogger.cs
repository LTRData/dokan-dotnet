using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace DokanNet.Logging;

/// <summary>
/// Log to the console.
/// </summary>
public class ConsoleLogger : ILogger, IDisposable
{
    private readonly string _loggerName;
    private readonly BlockingCollection<(string Message, ConsoleColor Color)> _PendingLogs = new();

    private readonly Thread _WriterTask = null;
    /// <summary>
    /// Initializes a new instance of the <see cref="ConsoleLogger"/> class.
    /// </summary>
    /// <param name="loggerName">Optional name to be added to each log line.</param>
    public ConsoleLogger(string loggerName = "")
    {
        _loggerName = loggerName;
        _WriterTask = new Thread(o =>
        {
            foreach (var (Message, Color) in _PendingLogs.GetConsumingEnumerable())
            {
                WriteMessage(Message, Color);
            }
        });
        _WriterTask.Start();
    }

    /// <inheritdoc />        
    public bool DebugEnabled => true;

    /// <inheritdoc />
    public void Debug(FormattableString message) => EnqueueMessage(Console.ForegroundColor, message);

    /// <inheritdoc />
    public void Info(FormattableString message) => EnqueueMessage(Console.ForegroundColor, message);

    /// <inheritdoc />
    public void Warn(FormattableString message) => EnqueueMessage(ConsoleColor.DarkYellow, message);

    /// <inheritdoc />
    public void Error(FormattableString message) => EnqueueMessage(ConsoleColor.Red, message);

    /// <inheritdoc />
    public void Fatal(FormattableString message) => EnqueueMessage(ConsoleColor.Red, message);

    private void EnqueueMessage(ConsoleColor newColor, FormattableString message) => _PendingLogs.Add((
            Message: message.FormatMessageForLogging(addDateTime: true, threadId: Environment.CurrentManagedThreadId, loggerName: _loggerName),
            Color: newColor));

    private static readonly object _lock = new();

    private void WriteMessage(string message, ConsoleColor newColor)
    {
        lock (_lock)
        {
            var origForegroundColor = Console.ForegroundColor;
            Console.ForegroundColor = newColor;
            Console.WriteLine(message);
            Console.ForegroundColor = origForegroundColor;
        }
    }

    #region IDisposable Support
    private bool disposedValue = false; // To detect redundant calls

    /// <summary>
    /// Wait and dispose pending log resources.
    /// </summary>
    /// <param name="disposing">Disposing resource.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            _PendingLogs.CompleteAdding();

            if (disposing)
            {
                // TODO: dispose managed state (managed objects).
                _WriterTask?.Join();
            }

            _PendingLogs.Dispose();

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.

            // TODO: set large fields to null.

            disposedValue = true;
        }
    }

    // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
    ~ConsoleLogger()
    {
        // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        Dispose(false);
    }

    /// <summary>
    /// Dispose resources.
    /// </summary>
    /// <remarks>This code added to correctly implement the disposable pattern.</remarks>
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        Dispose(true);
        // TODO: uncomment the following line if the finalizer is overridden above.
        GC.SuppressFinalize(this);
    }
    #endregion
}
