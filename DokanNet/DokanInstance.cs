using System;
using DokanNet.Native;

namespace DokanNet;

/// <summary>
/// Created by <see cref="Dokan.CreateFileSystem"/>.
/// It holds all the resources required to be alive for the time of the mount.
/// </summary>
public class DokanInstance : IDisposable
{
    internal NativeStructWrapper<DOKAN_OPTIONS> DokanOptions = null!;
    internal NativeStructWrapper<DOKAN_OPERATIONS> DokanOperations = null!;
    internal DokanHandle DokanHandle = null!;

    public event EventHandler? Disposing;

    public event EventHandler? Disposed;

    public bool IsDisposing { get; private set; }

    public bool IsDisposed { get; private set; }

    protected void OnDisposing(EventArgs e) => Disposing?.Invoke(this, e);

    protected void OnDisposed(EventArgs e) => Disposed?.Invoke(this, e);

    protected virtual void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            IsDisposing = true;

            if (disposing)
            {
                OnDisposing(EventArgs.Empty);

                // Dispose managed state (managed objects)
                DokanHandle?.Dispose();     // This calls DokanCloseHandle and waits for dismount
                DokanOptions?.Dispose();    // After that, it is safe to free unmanaged memory
                DokanOperations?.Dispose();

                OnDisposed(EventArgs.Empty);
            }

            // Free unmanaged resources (unmanaged objects) and override finalizer

            // Set fields to null
            DokanOptions = null!;
            DokanOperations = null!;
            DokanHandle = null!;

            IsDisposed = true;
        }
    }

    ~DokanInstance()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
