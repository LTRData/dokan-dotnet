using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using DokanNet.Native;

namespace DokanNet;

/// <summary>
/// Support for async/await operation on DokanInstance objects
/// </summary>
#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal sealed class DokanInstanceNotifyCompletion : ICriticalNotifyCompletion
{
    public DokanInstanceNotifyCompletion(DokanInstance dokanInstance, int milliSeconds)
    {
        DokanInstance = dokanInstance;
        MilliSeconds = milliSeconds;
    }

    public DokanInstance DokanInstance { get; }
    public int MilliSeconds { get; }
    public bool IsCompleted => !DokanInstance.IsFileSystemRunning();
    private nint waitHandle;
    private bool timedOut;

    public DokanInstanceNotifyCompletion GetAwaiter() => this;

    public void OnCompleted(Action continuation) => throw new NotSupportedException();

    public void UnsafeOnCompleted(Action continuation)
    {
        void callback(nint state, bool timedOut)
        {
            this.timedOut = timedOut;
            continuation();
        }

        if (!NativeMethods.DokanRegisterWaitForFileSystemClosed(DokanInstance.DokanHandle, out waitHandle, callback, 0, MilliSeconds))
        {
            throw new Win32Exception();
        }
    }

    /// <summary>
    /// Gets a value indicating whether DokanInstance was closed or if await timed out
    /// </summary>
    /// <returns>True if DokanInstance was closed or false if await timed out</returns>
    public bool GetResult()
    {
        if (!timedOut && !IsCompleted)
        {
            throw new InvalidOperationException("Invalid state for GetResult");
        }

        var handle = waitHandle;
        
        waitHandle = 0;

        if (handle != 0)
        {
            NativeMethods.DokanUnregisterWaitForFileSystemClosed(handle, waitForCallbacks: false);
        }

        return IsCompleted;
    }
}
