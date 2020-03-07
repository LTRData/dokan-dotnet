using System;
using System.Diagnostics;
using System.Threading;

namespace DokanNet
{
    public class DokanService : IDisposable
    {
        public event EventHandler Stopped;

        public event EventHandler<ThreadExceptionEventArgs> Error;

        public IDokanOperations Operations { get; }
        public string MountPoint { get; }
        public DokanOptions MountOptions { get; }
        public int ThreadCount { get; }
        public int Version { get; }
        public TimeSpan Timeout { get; }
        public string UncName { get; }
        public int AllocationUnitSize { get; }
        public int SectorSize { get; }
        public bool Running => _thread?.IsAlive ?? false;

        private Thread _thread;

        public DokanService(IDokanOperations operations, string mountPoint, DokanOptions mountOptions = 0,
            int threadCount = 1, int version = Dokan.DOKAN_VERSION, TimeSpan? timeout = null, string uncName = null,
            int allocationUnitSize = 512, int sectorSize = 512)
        {
            Operations = operations;
            MountPoint = mountPoint;
            MountOptions = mountOptions;
            ThreadCount = threadCount;
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

            _thread = new Thread(ServiceThread);

            _thread.Start();
        }

        private void ServiceThread()
        {
            try
            {
                Operations.Mount(MountPoint, MountOptions, ThreadCount, Version, Timeout, UncName, AllocationUnitSize, SectorSize);

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

        protected virtual void OnError(ThreadExceptionEventArgs e) => Error?.Invoke(this, e);

        protected virtual void OnDismounted(EventArgs e) => Stopped?.Invoke(this, e);

        #region IDisposable Support
        public bool IsDisposed { get; private set; } = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    if (_thread != null && _thread.IsAlive)
                    {
                        Trace.WriteLine($"Requesting dismount for Dokan file system '{MountPoint}'");

                        Dokan.RemoveMountPoint(MountPoint);

                        Trace.WriteLine($"Waiting for Dokan file system '{MountPoint}' service thread to stop");

                        _thread.Join();

                        Trace.WriteLine($"Dokan file system '{MountPoint}' service thread stopped.");
                    }

                    (Operations as IDisposable)?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.

                // TODO: set large fields to null.
                _thread = null;

                IsDisposed = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~DokanService()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}
