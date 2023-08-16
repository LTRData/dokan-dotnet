using System;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading;

namespace DokanNet;

#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
public class DokanService : IDisposable
{
    public event EventHandler? Stopped;

    public event EventHandler<ThreadExceptionEventArgs>? Error;

    public IDokanOperations Operations { get; }
    public string MountPoint { get; }
    public DokanOptions MountOptions { get; }
    public bool SingleThread { get; }
    public int Version { get; }
    public TimeSpan Timeout { get; }
    public string? UncName { get; }
    public int AllocationUnitSize { get; }
    public int SectorSize { get; }
    public bool Running => ServiceThread?.IsAlive ?? false;

    protected Thread? ServiceThread { get; private set; }

    public DokanService(IDokanOperations operations, string mountPoint, DokanOptions mountOptions = 0,
        bool singleThread = true, int version = Dokan.DOKAN_VERSION, TimeSpan? timeout = null, string? uncName = null,
        int allocationUnitSize = 512, int sectorSize = 512)
    {
        Operations = operations;
        MountPoint = mountPoint;
        MountOptions = mountOptions;
        SingleThread = singleThread;
        Version = version;
        Timeout = timeout ?? TimeSpan.FromSeconds(20);
        UncName = uncName;
        AllocationUnitSize = allocationUnitSize;
        SectorSize = sectorSize;
    }

    public void Start()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }

        ServiceThread = new Thread(ServiceThreadProcedure)
        {
            Name = "DokanService"
        };

        ServiceThread.Start();
    }

    private void ServiceThreadProcedure()
    {
        try
        {
            Operations.Mount(MountPoint, MountOptions, SingleThread, Version, Timeout, UncName, AllocationUnitSize, SectorSize);

            OnDismounted(EventArgs.Empty);
        }
        catch (Exception ex)
        {
            OnError(new ThreadExceptionEventArgs(ex));
        }
        finally
        {
            (Operations as IDisposable)?.Dispose();
        }
    }

    public void WaitExit()
    {
        if (ServiceThread == null ||
            ServiceThread.ManagedThreadId == Environment.CurrentManagedThreadId)
        {
            return;
        }

        ServiceThread.Join();
    }

    protected virtual void OnError(ThreadExceptionEventArgs e) => Error?.Invoke(this, e);

    protected virtual void OnDismounted(EventArgs e) => Stopped?.Invoke(this, e);

    #region IDisposable Support
    public bool IsDisposed => is_disposed != 0;

    int is_disposed;

    protected virtual void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref is_disposed, 1) == 0)
        {
            if (disposing)
            {
                // TODO: dispose managed state (managed objects).
                if (ServiceThread != null && ServiceThread.IsAlive)
                {
                    Trace.WriteLine($"Requesting dismount for Dokan file system '{MountPoint}'");

                    Dokan.RemoveMountPoint(MountPoint);

                    if (ServiceThread.ManagedThreadId != Environment.CurrentManagedThreadId)
                    {
                        Trace.WriteLine($"Waiting for Dokan file system '{MountPoint}' service thread to stop");

                        ServiceThread.Join();

                        Trace.WriteLine($"Dokan file system '{MountPoint}' service thread stopped.");
                    }
                }

                (Operations as IDisposable)?.Dispose();
            }

            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.

            // TODO: set large fields to null.
            ServiceThread = null;
        }
    }

    // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
    ~DokanService()
    {
        // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        Dispose(false);
    }

    // This code added to correctly implement the disposable pattern.
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        Dispose(true);
        // TODO: uncomment the following line if the finalizer is overridden above.
        GC.SuppressFinalize(this);
    }
    #endregion
}
