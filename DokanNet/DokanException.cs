using System;
using System.Runtime.Serialization;
using DokanNet.Properties;

namespace DokanNet;

/// <summary>
/// The dokan exception.
/// </summary>
[Serializable]
public class DokanException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DokanException"/> class with a <see cref="Exception.HResult"/>.
    /// </summary>
    /// <param name="status">
    /// The error status also written to <see cref="Exception.HResult"/>.
    /// </param>
    internal DokanException(DokanStatus status)
        : this(status, GetStatusErrorMessage(status)) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="DokanException"/> class with a <see cref="Exception.HResult"/>.
    /// </summary>
    /// <param name="status">
    /// The error status also written to <see cref="Exception.HResult"/>.
    /// </param>
    /// <param name="message">
    /// The error message.
    /// </param>
    internal DokanException(DokanStatus status, string message)
        : base(message)
    {
        ErrorStatus = status;
        HResult = (int)status;
    }

    private static string GetStatusErrorMessage(DokanStatus status) => status switch
    {
        DokanStatus.Error => Resources.ErrorDokan,
        DokanStatus.DriveLetterError => Resources.ErrorBadDriveLetter,
        DokanStatus.DriverInstallError => Resources.ErrorDriverInstall,
        DokanStatus.MountError => Resources.ErrorAssignDriveLetter,
        DokanStatus.StartError => Resources.ErrorStart,
        DokanStatus.MountPointError => Resources.ErrorMountPointInvalid,
        DokanStatus.VersionError => Resources.ErrorVersion,
        _ => Resources.ErrorUnknown,
    };

    /// <summary>
    /// Dokan error status <see cref="DokanStatus"/>.
    /// </summary>
    public DokanStatus ErrorStatus { get; private set; }

    public DokanException()
    {
    }

    public DokanException(string message) : base(message)
    {
    }

    public DokanException(string message, Exception innerException) : base(message, innerException)
    {
    }

    protected DokanException(SerializationInfo serializationInfo, StreamingContext streamingContext)
        : base(serializationInfo, streamingContext)
    {
        ErrorStatus = (DokanStatus)serializationInfo.GetValue("ErrorStatus", typeof(DokanStatus));
    }
}
