using System;

namespace DokanNet.Logging;

/// <summary>
/// Ignore all log messages.
/// </summary>
public class NullLogger : ILogger
{
    /// <inheritdoc />
    public bool DebugEnabled => false;

    /// <inheritdoc />
    public void Debug(FormattableString message)
    {
    }

    /// <inheritdoc />
    public void Error(FormattableString message)
    {
    }

    /// <inheritdoc />
    public void Fatal(FormattableString message)
    {
    }

    /// <inheritdoc />
    public void Info(FormattableString message)
    {
    }

    /// <inheritdoc />
    public void Warn(FormattableString message)
    {
    }
}
