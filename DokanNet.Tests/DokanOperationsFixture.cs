using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Moq;
using Moq.Language;
using static DokanNet.Tests.FileSettings;

namespace DokanNet.Tests;

internal sealed class DokanOperationsFixture
{
    private class Proxy : IDokanOperations
    {
        public IDokanOperations Target { get; set; }

        public bool HasUnmatchedInvocations { get; set; }

        #region Delegates
        private delegate TResult FuncOut2<in T1, T2, T3, out TResult>(T1 arg1, out T2 arg2, in T3 arg3);

        private delegate TResult FuncOut2<in T1, T2, in T3, T4, out TResult>(T1 arg1, out T2 arg2, T3 arg3, in T4 arg4);

        private delegate TResult FuncOut123<T1, T2, T3, T4, out TResult>(out T1 arg1, out T2 arg2, out T3 arg3, in T4 arg4);

        private delegate TResult FuncOut12345<T1, T2, T3, T4, T5, T6, out TResult>(out T1 arg1, out T2 arg2, out T3 arg3, out T4 arg4, ref T5 arg5, in T6 arg6);

        private delegate TResult FuncOut23<in T1, in T2, T3, T4, T5, out TResult>(T1 arg1, T2 arg2, out T3 arg3, out T4 arg4, in T5 arg5);

        private delegate TResult FuncOut3<in T1, in T2, T3, T4, out TResult>(T1 arg1, T2 arg2, out T3 arg3, in T4 arg4);

        protected delegate TResult FuncOut3<in T1, in T2, T3, in T4, T5, out TResult>(T1 arg1, T2 arg2, out T3 arg3, T4 arg4, in T5 arg5);
        #endregion

        #region private TryExecute overloads
        private void TryExecute(string fileName, in DokanFileInfo info, Action<string, DokanFileInfo> func, string funcName, bool restrictCallingProcessId = true)
        {
            if (restrictCallingProcessId && info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return;
            }

            try
            {
                func(fileName, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }
            }
        }

        private NtStatus TryExecute(in DokanFileInfo info, Func<DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} ({info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute(string fileName, in DokanFileInfo info, Func<string, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<T>(string fileName, T arg, in DokanFileInfo info, Func<string, T, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, arg, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {arg}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<T1, T2>(string fileName, T1 arg1, T2 arg2, in DokanFileInfo info, Func<string, T1, T2, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, arg1, arg2, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {arg1}, {arg2}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<T1, T2, T3>(string fileName, T1 arg1, T2 arg2, T3 arg3, in DokanFileInfo info, Func<string, T1, T2, T3, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, arg1, arg2, arg3, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {arg1}, {arg2}, {arg3}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TIn, TOut>(string fileName, TIn argIn, out TOut argOut, in DokanFileInfo info, FuncOut3<string, TIn, TOut, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, argIn, out argOut, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {argIn}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut = default;
                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TOut>(string fileName, out TOut argOut, in DokanFileInfo info, FuncOut2<string, TOut, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, out argOut, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut = default;
                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TOut, TIn>(string fileName, out TOut argOut, TIn argIn, in DokanFileInfo info, FuncOut2<string, TOut, TIn, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, out argOut, argIn, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {argIn}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut = default;
                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TIn1, TOut, TIn2>(string fileName, TIn1 argIn1, out TOut argOut, TIn2 argIn2, in DokanFileInfo info, FuncOut3<string, TIn1, TOut, TIn2, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(fileName, argIn1, out argOut, argIn2, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} (\"{fileName}\", {argIn1}, {argIn2}, {info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut = default;
                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TOut1, TOut2, TOut3, TOut4, TRef5>(out TOut1 argOut1, out TOut2 argOut2, out TOut3 argOut3, out TOut4 argOut4, ref TRef5 argRef5, in DokanFileInfo info, FuncOut12345<TOut1, TOut2, TOut3, TOut4, TRef5, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut1 = default;
                argOut2 = default;
                argOut3 = default;
                argOut4 = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(out argOut1, out argOut2, out argOut3, out argOut4, ref argRef5, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} ({info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut1 = default;
                argOut2 = default;
                argOut3 = default;
                argOut4 = default;
                return DokanResult.InvalidParameter;
            }
        }

        private NtStatus TryExecute<TOut1, TOut2, TOut3>(out TOut1 argOut1, out TOut2 argOut2, out TOut3 argOut3, in DokanFileInfo info, FuncOut123<TOut1, TOut2, TOut3, DokanFileInfo, NtStatus> func, string funcName)
        {
            if (info.ProcessId != Process.GetCurrentProcess().Id)
            {
                argOut1 = default;
                argOut2 = default;
                argOut3 = default;
                return DokanResult.AccessDenied;
            }

            try
            {
                return func(out argOut1, out argOut2, out argOut3, info);
            }
            catch (Exception ex)
            {
                Trace($"{funcName} ({info.Log()}) -> **{ex.GetType().Name}**: {ex.Message}\n{ex.StackTrace}");
                if (ex is MockException)
                {
                    HasUnmatchedInvocations = true;
                }

                argOut1 = default;
                argOut2 = default;
                argOut3 = default;
                return DokanResult.InvalidParameter;
            }
        }
        #endregion

        #region IDokanOperations members
        public void Cleanup(ReadOnlySpan<char> fileName, ref DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            TryExecute(fileName.ToString(), info, (f, i) => Target.Cleanup(f.AsSpan(), ref i), nameof(Cleanup), false);
        }

        public void CloseFile(ReadOnlySpan<char> fileName, ref DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            TryExecute(fileName.ToString(), info, (f, i) => Target.CloseFile(f.AsSpan(), ref i), nameof(CloseFile), false);
        }

        public NtStatus CreateFile(ReadOnlySpan<char> fileName, NativeFileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, ref DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), info, (f, i) => Target.CreateFile(f.AsSpan(), access, share, mode, options, attributes, ref i), nameof(CreateFile));
        }

        public NtStatus DeleteDirectory(ReadOnlySpan<char> fileName, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), info, (f, i) => Target.DeleteDirectory(f.AsSpan(), i), nameof(DeleteDirectory));
        }

        public NtStatus DeleteFile(ReadOnlySpan<char> fileName, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), info, (f, i) => Target.DeleteFile(f.AsSpan(), i), nameof(DeleteFile));
        }

        public NtStatus FindFiles(ReadOnlySpan<char> fileName, out IEnumerable<FindFileInformation> files, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), out files, info, (string f, out IEnumerable<FindFileInformation> o, in DokanFileInfo i) => Target.FindFiles(f.AsSpan(), out o, i), nameof(FindFiles));
        }

        public NtStatus FindFilesWithPattern(ReadOnlySpan<char> fileName, ReadOnlySpan<char> searchPattern, out IEnumerable<FindFileInformation> files, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), searchPattern.ToString(), out files, info, (string f, string s, out IEnumerable<FindFileInformation> o, in DokanFileInfo i) => Target.FindFilesWithPattern(f.AsSpan(), s.AsSpan(), out o, i), nameof(FindFilesWithPattern));
        }

        public NtStatus FindStreams(ReadOnlySpan<char> fileName, out IEnumerable<FindFileInformation> streams, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), out streams, info, (string f, out IEnumerable<FindFileInformation> o, in DokanFileInfo i) => Target.FindStreams(f.AsSpan(), out o, i), nameof(FindStreams));
        }

        public NtStatus FlushFileBuffers(ReadOnlySpan<char> fileName, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), info, (f, i) => Target.FlushFileBuffers(f.AsSpan(), i), nameof(FlushFileBuffers));
        }

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(out freeBytesAvailable, out totalNumberOfBytes, out totalNumberOfFreeBytes, info, (out long a, out long t, out long f, in DokanFileInfo i) => Target.GetDiskFreeSpace(out a, out t, out f, i), nameof(GetDiskFreeSpace));
        }

        public NtStatus GetFileInformation(ReadOnlySpan<char> fileName, out ByHandleFileInformation fileInfo, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), out fileInfo, info, (string f, out ByHandleFileInformation fi, in DokanFileInfo i) => Target.GetFileInformation(f.AsSpan(), out fi, i), nameof(GetFileInformation));
        }

        public NtStatus GetFileSecurity(ReadOnlySpan<char> fileName, out FileSystemSecurity security, AccessControlSections sections, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), out security, sections, info, (string f, out FileSystemSecurity s, AccessControlSections a, in DokanFileInfo i) => Target.GetFileSecurity(f.AsSpan(), out s, a, i), nameof(GetFileSecurity));
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features, out string fileSystemName, out uint maximumComponentLength, ref uint volumeSerialNumber, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(out volumeLabel, out features, out fileSystemName, out maximumComponentLength, ref volumeSerialNumber, info, (out string v, out FileSystemFeatures f, out string n, out uint c, ref uint id, in DokanFileInfo i) => Target.GetVolumeInformation(out v, out f, out n, out c, ref id, i), nameof(GetVolumeInformation));
        }

        public NtStatus LockFile(ReadOnlySpan<char> fileName, long offset, long length, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), offset, length, info, (f, o, l, i) => Target.LockFile(f.AsSpan(), o, l, i), nameof(LockFile));
        }

        public NtStatus MoveFile(ReadOnlySpan<char> oldName, ReadOnlySpan<char> newName, bool replace, ref DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(oldName.ToString(), newName.ToString(), replace, info, (o, n, r, i) => Target.MoveFile(o.AsSpan(), n.AsSpan(), r, ref i), nameof(MoveFile));
        }

        public NtStatus ReadFile(ReadOnlySpan<char> fileName, Span<byte> buffer, out int bytesRead, long offset, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            var array = new byte[buffer.Length];
            var rc = TryExecute(fileName.ToString(), array, out bytesRead, offset, info, (string f, byte[] b, out int r, long o, in DokanFileInfo i) => Target.ReadFile(f.AsSpan(), b.AsSpan(), out r, o, i), nameof(ReadFile));
            array.CopyTo(buffer);
            return rc;
        }

        public NtStatus SetAllocationSize(ReadOnlySpan<char> fileName, long length, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), length, info, (f, l, i) => Target.SetAllocationSize(f.AsSpan(), l, i), nameof(SetAllocationSize));
        }

        public NtStatus SetEndOfFile(ReadOnlySpan<char> fileName, long length, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), length, info, (f, l, i) => Target.SetEndOfFile(f.AsSpan(), l, i), nameof(SetEndOfFile));
        }

        public NtStatus SetFileAttributes(ReadOnlySpan<char> fileName, FileAttributes attributes, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), attributes, info, (f, a, i) => Target.SetFileAttributes(f.AsSpan(), a, i), nameof(SetFileAttributes));
        }

        public NtStatus SetFileSecurity(ReadOnlySpan<char> fileName, FileSystemSecurity security, AccessControlSections sections, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), security, sections, info, (f, s, a, i) => Target.SetFileSecurity(f.AsSpan(), s, a, i), nameof(SetFileSecurity));
        }

        public NtStatus SetFileTime(ReadOnlySpan<char> fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), creationTime, lastAccessTime, lastWriteTime, info, (f, c, a, w, i) => Target.SetFileTime(f.AsSpan(), c, a, w, i), nameof(SetFileTime));
        }

        public NtStatus UnlockFile(ReadOnlySpan<char> fileName, long offset, long length, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), offset, length, info, (f, o, l, i) => Target.UnlockFile(f.AsSpan(), o, l, i), nameof(UnlockFile));
        }

        public NtStatus Mounted(ReadOnlySpan<char> mountPoint, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(mountPoint.ToString(), info, (m, i) => Target.Mounted(m.AsSpan(), i), nameof(Mounted));
        }

        public NtStatus Unmounted(in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(info, i => Target.Unmounted(i), nameof(Unmounted));
        }
        public NtStatus WriteFile(ReadOnlySpan<char> fileName, ReadOnlySpan<byte> buffer, out int bytesWritten, long offset, in DokanFileInfo info)
        {
            if (info.ProcessId == 0)
            {
                throw new ArgumentException("Not in DokanFileInfo", nameof(info));
            }

            return TryExecute(fileName.ToString(), buffer.ToArray(), out bytesWritten, offset, info, (string f, byte[] b, out int w, long o, in DokanFileInfo i) => Target.WriteFile(f.AsSpan(), b, out w, o, i), nameof(WriteFile));
        }
        #endregion
    }

    /// <summary>The mount point in use for the <see cref="IDokanOperations"/> implementation.</summary>
    public static string NormalMountPoint { get; private set; }

    /// <summary>
    /// Initializes the mount points by finding the next available drive letters.
    /// </summary>
    private static void InitMountPoints()
    {
        var drives = Environment.GetLogicalDrives()
            .Select(x => x[0])
            .ToArray();

        var alphabet = new Stack<char>("ABCDEFGHILMNOPQRSTUVZ");

        NormalMountPoint = GetMountPoint();

        string GetMountPoint()
        {
            while (alphabet.Any())
            {
                var letter = alphabet.Pop();
                if (!drives.Contains(letter))
                {
                    return $"{letter}:";
                }
            }

            throw new InvalidOperationException("No drive letters available to test with.");
        }
    }

    public static string MOUNT_POINT { get; private set; }

    public const string VOLUME_LABEL = "Dokan Volume";

    public const string FILESYSTEM_NAME = "Dokan Test";

    internal const int PROBE_BUFFER_SIZE = 512;

    private const FileSystemFeatures TestFileSystemFeatures =
        FileSystemFeatures.CasePreservedNames | FileSystemFeatures.CaseSensitiveSearch |
        FileSystemFeatures.SupportsRemoteStorage | FileSystemFeatures.UnicodeOnDisk;

    private const FileAttributes EmptyFileAttributes = default;

    private static readonly Proxy proxy = new();
    private readonly string currentTestName;

    private readonly Mock<IDokanOperations> operations = new(MockBehavior.Strict);

    private long pendingFiles;

    public static bool HasPendingFiles => Instance?.pendingFiles > 0;

    internal static IDokanOperations Operations => proxy;

    internal static DokanOperationsFixture Instance { get; private set; }

    internal static string DriveName => MOUNT_POINT;

    internal static string RootName => @"\";

    private const string fileName = "File.ext";

    private const string destinationFileName = "DestinationFile.txe";

    private const string destinationBackupFileName = "BackupFile.txe";

    private const string directoryName = "Dir";

    private const string directory2Name = "Dir2";

    private const string destinationDirectoryName = "DestinationDir";

    private const string subDirectoryName = "SubDir";

    private const string subDirectory2Name = "SubDir2";

    private const string destinationSubDirectoryName = "DestinationSubDir";

    private static readonly FindFileInformation[] rootDirectoryItems =
    {
        new FindFileInformation()
        {
            FileName = directoryName.AsMemory(), Attributes = FileAttributes.Directory,
            CreationTime = ToDateTime("2015-01-01 10:11:12"), LastWriteTime = ToDateTime("2015-01-01 20:21:22"), LastAccessTime = ToDateTime("2015-01-01 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = directory2Name.AsMemory(), Attributes = FileAttributes.Directory,
            CreationTime = ToDateTime("2015-01-01 13:14:15"), LastWriteTime = ToDateTime("2015-01-01 23:24:25"), LastAccessTime = ToDateTime("2015-01-01 23:24:25")
        },
        new FindFileInformation()
        {
            FileName = fileName.AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-01-02 10:11:12"), LastWriteTime = ToDateTime("2015-01-02 20:21:22"), LastAccessTime = ToDateTime("2015-01-02 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SecondFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-01-03 10:11:12"), LastWriteTime = ToDateTime("2015-01-03 20:21:22"), LastAccessTime = ToDateTime("2015-01-03 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "ThirdFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-01-04 10:11:12"), LastWriteTime = ToDateTime("2015-01-04 20:21:22"), LastAccessTime = ToDateTime("2015-01-04 20:21:22")
        }
    };

    private static readonly FindFileInformation[] directoryItems =
    {
        new FindFileInformation()
        {
            FileName = subDirectoryName.AsMemory(), Attributes = FileAttributes.Directory,
            CreationTime = ToDateTime("2015-02-01 10:11:12"), LastWriteTime = ToDateTime("2015-02-01 20:21:22"), LastAccessTime = ToDateTime("2015-02-01 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-02 10:11:12"), LastWriteTime = ToDateTime("2015-02-02 20:21:22"), LastAccessTime = ToDateTime("2015-02-02 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SecondSubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-03 10:11:12"), LastWriteTime = ToDateTime("2015-02-03 20:21:22"), LastAccessTime = ToDateTime("2015-02-03 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "ThirdSubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-04 10:11:12"), LastWriteTime = ToDateTime("2015-02-04 20:21:22"), LastAccessTime = ToDateTime("2015-02-04 20:21:22")
        }
    };

    private static readonly FindFileInformation[] directory2Items =
    {
        new FindFileInformation()
        {
            FileName = subDirectory2Name.AsMemory(), Attributes = FileAttributes.Directory,
            CreationTime = ToDateTime("2015-02-01 10:11:12"), LastWriteTime = ToDateTime("2015-02-01 20:21:22"), LastAccessTime = ToDateTime("2015-02-01 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SubFile2.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-02 10:11:12"), LastWriteTime = ToDateTime("2015-02-02 20:21:22"), LastAccessTime = ToDateTime("2015-02-02 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SecondSubFile2.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-03 10:11:12"), LastWriteTime = ToDateTime("2015-02-03 20:21:22"), LastAccessTime = ToDateTime("2015-02-03 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "ThirdSubFile2.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-02-04 10:11:12"), LastWriteTime = ToDateTime("2015-02-04 20:21:22"), LastAccessTime = ToDateTime("2015-02-04 20:21:22")
        }
    };

    private static readonly FindFileInformation[] subDirectoryItems =
    {
        new FindFileInformation()
        {
            FileName = "SubSubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-03-01 10:11:12"), LastWriteTime = ToDateTime("2015-03-01 20:21:22"), LastAccessTime = ToDateTime("2015-03-01 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "SecondSubSubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-03-02 10:11:12"), LastWriteTime = ToDateTime("2015-03-02 20:21:22"), LastAccessTime = ToDateTime("2015-03-02 20:21:22")
        },
        new FindFileInformation()
        {
            FileName = "ThirdSubSubFile.ext".AsMemory(), Attributes = FileAttributes.Normal,
            CreationTime = ToDateTime("2015-03-03 10:11:12"), LastWriteTime = ToDateTime("2015-03-03 20:21:22"), LastAccessTime = ToDateTime("2015-03-03 20:21:22")
        }
    };

    internal static DirectorySecurity DefaultDirectorySecurity { get; private set; }

    internal static FileSecurity DefaultFileSecurity { get; private set; }

    internal static TimeSpan IODelay = TimeSpan.FromSeconds(19);

    internal string FileName => Named(fileName);

    internal string DestinationFileName => Named(destinationFileName);

    internal string DestinationBackupFileName => Named(destinationBackupFileName);

    internal string DirectoryName => Named(directoryName);

    internal string Directory2Name => Named(directory2Name);

    internal string DestinationDirectoryName => Named(destinationDirectoryName);

    internal string SubDirectoryName => Named(subDirectoryName);

    internal string SubDirectory2Name => Named(subDirectory2Name);

    internal string DestinationSubDirectoryName => Named(destinationSubDirectoryName);

    internal FindFileInformation[] RootDirectoryItems => Named(rootDirectoryItems);

    internal FindFileInformation[] DirectoryItems => Named(directoryItems);

    internal FindFileInformation[] Directory2Items => Named(directory2Items);

    internal FindFileInformation[] SubDirectoryItems => Named(subDirectoryItems);

    static DokanOperationsFixture()
    {
        InitInstance(string.Empty);
        Instance.PermitMount();

        InitSecurity();
        InitMountPoints();
    }

    private static DateTime ToDateTime(string value) => DateTime.Parse(value, CultureInfo.InvariantCulture);

    internal static int NumberOfChunks(long bufferSize, long fileSize)
    {
        var quotient = Math.DivRem(fileSize, bufferSize, out var remainder);
        return (int)quotient + (remainder > 0 ? 1 : 0);
    }

    internal static string DriveBasedPath(ReadOnlySpan<char> fileName)
        => DriveName + RootedPath(fileName);

    internal static string RootedPath(ReadOnlySpan<char> fileName)
        => Path.DirectorySeparatorChar + fileName.TrimStart(Path.DirectorySeparatorChar).ToString();

    /// <summary>
    /// Initializes the test fixture for running a test.
    /// </summary>
    /// <param name="currentTestName">The name of the test.</param>
    /// <param name="unsafeOperations">True to test IDokanOperationsUnsafe, false to test IDokanOperations.</param>
    internal static void InitInstance(string currentTestName)
    {
        Instance = new DokanOperationsFixture(currentTestName);

        proxy.Target = Instance.operations.Object;
        proxy.HasUnmatchedInvocations = false;

        // Choose the mount point to operate on based on whether we're testing IDokanOperation of IDokanOperationsUnsafe.
        MOUNT_POINT = NormalMountPoint;
    }

    internal static void ClearInstance(out bool hasUnmatchedInvocations)
    {
        // Allow pending calls to process
        Thread.Sleep(1);

        var proxyInUse = proxy;
        hasUnmatchedInvocations = proxyInUse.HasUnmatchedInvocations;

        proxy.Target = null;
        Instance = null;
        MOUNT_POINT = null;
    }

    internal static void Trace(string message) => Console.WriteLine(message);

    internal static void InitSecurity()
    {
        var sid = WindowsIdentity.GetCurrent();

        var sidRights = $"O:{sid.User}G:{sid.Groups[0]}";

        DefaultDirectorySecurity = new DirectorySecurity();
        DefaultDirectorySecurity.SetSecurityDescriptorSddlForm($"{sidRights}D:PAI(A;OICI;FA;;;AU)");

        DefaultFileSecurity = new FileSecurity();
        DefaultFileSecurity.SetSecurityDescriptorSddlForm($"{sidRights}D:AI(A;ID;FA;;;AU)");
    }

    internal static IList<FindFileInformation> GetEmptyDirectoryDefaultFiles()
        => new[]
        {
            new FindFileInformation()
            {
                FileName = ".".AsMemory(), Attributes = FileAttributes.Directory,
                CreationTime = DateTime.Today, LastWriteTime = DateTime.Today, LastAccessTime = DateTime.Today
            },
            new FindFileInformation()
            {
                FileName = "..".AsMemory(), Attributes = FileAttributes.Directory,
                CreationTime = DateTime.Today, LastWriteTime = DateTime.Today, LastAccessTime = DateTime.Today
            }
        };

    internal static IList<FindFileInformation> RemoveDatesFromFileInformations(IEnumerable<FindFileInformation> fileInformations)
    {
        return fileInformations
            .Select(x => new FindFileInformation()
            {
                FileName = x.FileName,
                Attributes = x.Attributes,
                CreationTime = null,
                LastAccessTime = null,
                LastWriteTime = null,
                Length = x.Length
            }).ToArray();
    }

    internal static byte[] InitPeriodicTestData(long fileSize)
        => Enumerable.Range(0, (int)fileSize).Select(i => (byte)(i % 251)).ToArray();

    internal static byte[] InitBlockTestData(long bufferSize, long fileSize)
        => Enumerable.Range(0, (int)fileSize).Select(i => (byte)(i / bufferSize + 1)).ToArray();

    public DokanOperationsFixture(string currentTestName)
    {
        this.currentTestName = currentTestName;
    }

#if !SPECIFIC_NAMES
    private string Named(string name) => name;
#else
    private string Named(string name) => $"{currentTestName}_{name}";
#endif

    private FindFileInformation[] Named(FindFileInformation[] infos)
        => infos.Aggregate(new List<FindFileInformation>(), (l, i) => { l.Add(Named(i)); return l; }, l => l.ToArray());

    private FindFileInformation Named(FindFileInformation info) => new()
    {
        FileName = Named(info.FileName.ToString()).AsMemory(),
        Attributes = info.Attributes,
        CreationTime = info.CreationTime,
        LastAccessTime = info.LastAccessTime,
        LastWriteTime = info.LastWriteTime,
        Length = info.Length
    };

    private static Func<DokanFileInfo, bool> FilterByIsDirectory(bool? isDirectory)
        => f => !isDirectory.HasValue || f.IsDirectory == isDirectory.Value;

    internal void PermitAny()
    {
        operations
            .Setup(d => d.Cleanup(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Callback((ReadOnlySpan<char> fileName, in DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Cleanup)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));

        operations
            .Setup(d => d.CloseFile(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Callback((ReadOnlySpan<char> fileName, in DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CloseFile)}[{Interlocked.Decrement(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));

        operations
            .Setup(d => d.CreateFile(It.IsAny<string>().AsSpan(), It.IsAny<NativeFileAccess>(), It.IsAny<FileShare>(), It.IsAny<FileMode>(), It.IsAny<FileOptions>(), It.IsAny<FileAttributes>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CreateFile)}[{Interlocked.Increment(ref pendingFiles)}] (\"{fileName}\", [{access}], [{share}], {mode}, [{options}], [{attributes}], {info.Log()})"));

        operations
            .Setup(d => d.DeleteDirectory(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.DeleteDirectory)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));

        operations
            .Setup(d => d.DeleteFile(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.DeleteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));

        var files = GetEmptyDirectoryDefaultFiles().AsEnumerable();
        operations
            .Setup(d => d.FindFiles(It.IsAny<string>().AsSpan(), out files, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, IEnumerable<FindFileInformation> _files, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FindFiles)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_files.Count}], {info.Log()})"));

        operations
            .Setup(d => d.FlushFileBuffers(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FlushFileBuffers)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));

        long freeBytesAvailable = 0;
        long totalNumberOfBytes = 0;
        long totalNumberOfFreeBytes = 0;
        operations
            .Setup(d => d.GetDiskFreeSpace(out freeBytesAvailable, out totalNumberOfBytes, out totalNumberOfFreeBytes, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((long _freeBytesAvailable, long _totalNumberOfBytes, long _totalNumberOfFreeBytes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetDiskFreeSpace)}[{Interlocked.Read(ref pendingFiles)}] (out {_freeBytesAvailable}, out {_totalNumberOfBytes}, out {_totalNumberOfFreeBytes}, {info.Log()})"));

        var directoryInfo = new ByHandleFileInformation()
        {
            Attributes = FileAttributes.Directory,
            CreationTime = new DateTime(2015, 1, 1, 12, 0, 0),
            LastWriteTime = new DateTime(2015, 3, 31, 12, 0, 0),
            LastAccessTime = new DateTime(2015, 5, 31, 12, 0, 0)
        };
        operations
            .Setup(d => d.GetFileInformation(It.IsAny<string>().AsSpan(), out directoryInfo, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FindFileInformation _directoryInfo, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileInformation)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_directoryInfo.Log()}], {info.Log()})"));
        var fileInfo = new ByHandleFileInformation()
        {
            Attributes = FileAttributes.Normal,
            CreationTime = new DateTime(2015, 1, 1, 12, 0, 0),
            LastWriteTime = new DateTime(2015, 3, 31, 12, 0, 0),
            LastAccessTime = new DateTime(2015, 5, 31, 12, 0, 0),
            Length = 1024
        };
        operations
            .Setup(d => d.GetFileInformation(It.IsAny<string>().AsSpan(), out fileInfo, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FindFileInformation _fileInfo, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileInformation)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_fileInfo.Log()}], {info.Log()})"));

        var fileSecurity = new FileSecurity() as FileSystemSecurity;
        operations
            .Setup(d => d.GetFileSecurity(It.IsAny<string>().AsSpan(), out fileSecurity, It.IsAny<AccessControlSections>(), It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileSystemSecurity _fileSecurity, AccessControlSections sections, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileSecurity)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out {_fileSecurity}, {sections}, {info.Log()})"));
        var directorySecurity = new DirectorySecurity() as FileSystemSecurity;
        operations
            .Setup(d => d.GetFileSecurity(It.IsAny<string>().AsSpan(), out directorySecurity, It.IsAny<AccessControlSections>(), It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileSystemSecurity _directorySecurity, AccessControlSections sections, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileSecurity)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out {_directorySecurity}, {sections}, {info.Log()})"));

        var volumeLabel = VOLUME_LABEL;
        var features = TestFileSystemFeatures;
        var fileSystemName = FILESYSTEM_NAME;
        var volumeSerialNumber = 0u;
        uint maximumComponentLength = 256;
        operations
            .Setup(d => d.GetVolumeInformation(out volumeLabel, out features, out fileSystemName, out maximumComponentLength, ref volumeSerialNumber, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string _volumeLabel, FileSystemFeatures _features, string _fileSystemName, uint _maximumComponentLength, uint _volumeSerialNumber, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetVolumeInformation)}[{Interlocked.Read(ref pendingFiles)}] (out \"{_volumeLabel}\", out [{_features}], out \"{_fileSystemName}\", out \"{_maximumComponentLength}\", {info.Log()})"));

        operations
            .Setup(d => d.LockFile(It.IsAny<string>().AsSpan(), It.IsAny<long>(), It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long offset, long length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.LockFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {offset}, {length}, {info.Log()})"));

        operations
            .Setup(d => d.MoveFile(It.IsAny<string>().AsSpan(), It.IsAny<string>().AsSpan(), It.IsAny<bool>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string oldName, string newName, bool replace, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.MoveFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{oldName}\", \"{newName}\", {replace}, {info.Log()})"));

        var bytesRead = 0;
        operations
            .Setup(d => d.ReadFile(It.IsAny<string>().AsSpan(), It.IsAny<byte[]>(), out bytesRead, It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] buffer, int _bytesRead, long offset, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.ReadFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{buffer.Length}], out {_bytesRead}, {offset}, {info.Log()})"));

        operations
            .Setup(d => d.SetAllocationSize(It.IsAny<string>().AsSpan(), It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetAllocationSize)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {length}, {info.Log()})"));

        operations
            .Setup(d => d.SetEndOfFile(It.IsAny<string>().AsSpan(), It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetEndOfFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {length}, {info.Log()})"));

        operations
            .Setup(d => d.SetFileAttributes(It.IsAny<string>().AsSpan(), It.IsAny<FileAttributes>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAttributes attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileAttributes)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{attributes}], {info.Log()})"));

        operations
            .Setup(d => d.SetFileSecurity(It.IsAny<string>().AsSpan(), It.IsAny<FileSystemSecurity>(), It.IsAny<AccessControlSections>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileSystemSecurity security, AccessControlSections sections, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileSecurity)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{security}], {sections}, {info.Log()})"));

        operations
            .Setup(d => d.SetFileTime(It.IsAny<string>().AsSpan(), It.IsAny<DateTime?>(), It.IsAny<DateTime?>(), It.IsAny<DateTime?>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileTime)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {creationTime}, {lastAccessTime}, {lastWriteTime}, {info.Log()})"));

        operations
            .Setup(d => d.UnlockFile(It.IsAny<string>().AsSpan(), It.IsAny<long>(), It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long offset, long length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.UnlockFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {offset}, {length}, {info.Log()})"));

        operations
            .Setup(d => d.Mounted(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string mountPoint, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Mounted)}[{Interlocked.Read(ref pendingFiles)}] ({info.Log()})"));

        operations
            .Setup(d => d.Unmounted(It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Unmounted)}[{Interlocked.Read(ref pendingFiles)}] ({info.Log()})"));

        var bytesWritten = 0;
        operations
            .Setup(d => d.WriteFile(It.IsAny<string>().AsSpan(), It.IsAny<byte[]>(), out bytesWritten, It.IsAny<long>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] buffer, int _bytesWritten, long offset, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.WriteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{buffer.Length}], out {_bytesWritten}, {offset}, {info.Log()})"));
    }

    private void PermitMount()
    {
        operations
            .Setup(d => d.Mounted(It.IsAny<string>().AsSpan(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string mountPoint, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Mounted)} {info.Log()}"));
        operations
            .Setup(d => d.CreateFile(RootName.AsSpan(), NativeFileAccess.ReadAttributes, ReadWriteShare, FileMode.Open, FileOptions.None, EmptyFileAttributes, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CreateFile)}[{Interlocked.Increment(ref pendingFiles)}] (\"{fileName}\", [{access}], [{share}], {mode}, [{options}], [{attributes}], {info.Log()})"));
        var fileInfo = new ByHandleFileInformation()
        {
            Attributes = FileAttributes.Directory,
            CreationTime = new DateTime(2015, 1, 1, 12, 0, 0),
            LastWriteTime = new DateTime(2015, 3, 31, 12, 0, 0),
            LastAccessTime = new DateTime(2015, 3, 31, 12, 0, 0)
        };
        operations
            .Setup(d => d.GetFileInformation(RootName.AsSpan(), out fileInfo, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FindFileInformation _fileInfo, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileInformation)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_fileInfo.Log()}], {info.Log()})"));
        operations
            .Setup(d => d.Cleanup(RootName.AsSpan(), It.IsAny<DokanFileInfo>()))
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Cleanup)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));
        operations
            .Setup(d => d.CloseFile(RootName.AsSpan(), It.IsAny<DokanFileInfo>()))
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CloseFile)}[{Interlocked.Decrement(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"));
    }

    internal void ExpectGetDiskFreeSpace(long freeBytesAvailable = 0, long totalNumberOfBytes = 0,
        long totalNumberOfFreeBytes = 0)
    {
        ExpectOpenDirectory(RootName, OpenDirectoryAccess, OpenDirectoryShare);

        operations
            .Setup(d => d.GetDiskFreeSpace(out freeBytesAvailable, out totalNumberOfBytes, out totalNumberOfFreeBytes, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((long _freeBytesAvailable, long _totalNumberOfBytes, long _totalNumberOfFreeBytes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetDiskFreeSpace)}[{Interlocked.Read(ref pendingFiles)}] (out {_freeBytesAvailable}, out {_totalNumberOfBytes}, out {_totalNumberOfFreeBytes}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectGetVolumeInformation(string volumeLabel, string fileSystemName, uint maximumComponentLength, ref uint volumeSerialNumber)
    {
        var features = TestFileSystemFeatures;
        operations
            .Setup(d => d.GetVolumeInformation(out volumeLabel, out features, out fileSystemName, out maximumComponentLength, ref volumeSerialNumber, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string _volumeLabel, FileSystemFeatures _features, string _fileSystemName, uint _maximumComponentLength, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetVolumeInformation)}[{Interlocked.Read(ref pendingFiles)}] (out \"{_volumeLabel}\", out [{_features}], out \"{_fileSystemName}\", out \"{_maximumComponentLength}\", {info.Log()})"))
            .Verifiable();
    }

    private IVerifies SetupGetFileInformation(string path, FileAttributes attributes, bool? isDirectory = null, DateTime? creationTime = null, DateTime? lastWriteTime = null, DateTime? lastAccessTime = null, long? length = null)
    {
        var fileInfo = new ByHandleFileInformation()
        {
            Attributes = attributes,
            CreationTime = creationTime,
            LastWriteTime = lastWriteTime,
            LastAccessTime = lastAccessTime,
            Length = length ?? 0
        };
        return operations
            .Setup(d => d.GetFileInformation(path.AsSpan(), out fileInfo, It.Is<DokanFileInfo>(i => FilterByIsDirectory(isDirectory)(i))))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FindFileInformation _fileInfo, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileInformation)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_fileInfo.Log()}], {info.Log()})"));
    }

    internal void PermitGetFileInformation(string path, FileAttributes attributes, bool? isDirectory = null, DateTime? creationTime = null, DateTime? lastWriteTime = null, DateTime? lastAccessTime = null, long? length = null) => SetupGetFileInformation(path, attributes, isDirectory, creationTime, lastWriteTime, lastAccessTime, length);

    internal void ExpectGetFileInformation(string path, FileAttributes attributes, bool? isDirectory = null, DateTime? creationTime = null, DateTime? lastWriteTime = null, DateTime? lastAccessTime = null, long? length = null)
    {
        SetupGetFileInformation(path, attributes, isDirectory, creationTime, lastWriteTime, lastAccessTime, length)
            .Verifiable();
    }

    private IVerifies SetupGetFileInformationToFail(string path, NtStatus result, bool? isDirectory = null)
    {
        if (result == DokanResult.Success)
        {
            throw new ArgumentException($"{DokanResult.Success} not supported", nameof(result));
        }

        var fileInfo = default(ByHandleFileInformation);
        return operations
            .Setup(d => d.GetFileInformation(path.AsSpan(), out fileInfo, It.Is<DokanFileInfo>(i => FilterByIsDirectory(isDirectory)(i))))
            .Returns(result)
            .Callback((ReadOnlySpan<char> fileName, FindFileInformation _fileInfo, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileInformation)}[{Interlocked.Read(ref pendingFiles)}] **{result}** (\"{fileName}\", out [{_fileInfo.Log()}], {info.Log()})"));
    }

    internal void PermitGetFileInformationToFail(string path, NtStatus result, bool? isDirectory = null) => SetupGetFileInformationToFail(path, result, isDirectory);

    internal void ExpectGetFileInformationToFail(string path, NtStatus result, bool? isDirectory = null) => SetupGetFileInformationToFail(path, result, isDirectory).Verifiable();

    internal void ExpectFindFiles(string path, IEnumerable<FindFileInformation> fileInfos)
    {
        operations
            .Setup(d => d.FindFiles(path.AsSpan(), out fileInfos, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, IList<FindFileInformation> _files, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FindFiles)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_files.Count}], {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectFindFilesWithPattern(string path, string searchPattern, IEnumerable<FindFileInformation> fileInfos)
    {
        operations
            .Setup(d => d.FindFilesWithPattern(path.AsSpan(), searchPattern.AsSpan(), out fileInfos, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, string _searchPattern, IList<FindFileInformation> _files, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FindFilesWithPattern)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", \"{_searchPattern}\", out [{_files.Count}], {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectFindFilesWithPatternToFail(string path, string searchPattern, NtStatus result)
    {
        var fileInfos = new List<FindFileInformation>() as IEnumerable<FindFileInformation>;
        operations
            .Setup(d => d.FindFilesWithPattern(path.AsSpan(), searchPattern.AsSpan(), out fileInfos, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(result)
            .Callback((ReadOnlySpan<char> fileName, string _searchPattern, IList<FindFileInformation> _files, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FindFilesWithPattern)}[{Interlocked.Read(ref pendingFiles)}] **{result}** (\"{fileName}\", \"{_searchPattern}\", out [{_files.Count}], {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectOpenDirectoryWithoutCleanup(string path, NativeFileAccess access = NativeFileAccess.Synchronize, FileShare share = FileShare.None, FileAttributes attributes = EmptyFileAttributes)
    {
        operations
            .Setup(d => d.CreateFile(path.AsSpan(), FileAccessUtils.MapSpecificToGenericAccess(access), share, FileMode.Open, ReadFileOptions, attributes, It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAccess _access, FileShare _share, FileMode mode, FileOptions options, FileAttributes _attributes, DokanFileInfo info)
                    => Trace($"{nameof(IDokanOperations.CreateFile)}-NoCleanup[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_access}], [{_share}], {mode}, [{options}], [{_attributes}], {info.Log()})"))
            .Verifiable();
    }

    internal void PermitOpenDirectory(string path, NativeFileAccess access = ReadDirectoryAccess, FileShare share = ReadWriteShare, FileOptions options = ReadFileOptions, FileAttributes attributes = EmptyFileAttributes) => PermitCreateDirectory(path, access, share, FileMode.Open, options, attributes);

    internal void ExpectOpenDirectory(string path, NativeFileAccess access = ReadDirectoryAccess, FileShare share = ReadWriteShare, FileOptions options = ReadFileOptions, FileAttributes attributes = EmptyFileAttributes) => ExpectCreateDirectory(path, access, share, FileMode.Open, options, attributes);

    private IVerifies[] SetupCreateDirectory(string path, NativeFileAccess access = ReadDirectoryAccess, FileShare share = FileShare.ReadWrite, FileMode mode = FileMode.CreateNew, FileOptions options = FileOptions.None, FileAttributes attributes = FileAttributes.Normal)
    {
        return new[]
        {
            operations
                .Setup(d => d.CreateFile(path.AsSpan(), FileAccessUtils.MapSpecificToGenericAccess(access), share, mode, options, attributes, It.Is<DokanFileInfo>(i => i.IsDirectory)))
                .Returns(DokanResult.Success)
                .Callback((ReadOnlySpan<char> fileName, FileAccess _access, FileShare _share, FileMode _mode, FileOptions _options, FileAttributes _attributes, DokanFileInfo info)
                    => Trace($"{nameof(IDokanOperations.CreateFile)}[{Interlocked.Increment(ref pendingFiles)}] (\"{fileName}\", [{_access}], [{_share}], {_mode}, [{_options}], [{_attributes}], {info.Log()})")),
            operations
                .Setup(d => d.Cleanup(path.AsSpan(), It.Is<DokanFileInfo>(i => i.IsDirectory)))
                .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                    => Trace($"{nameof(IDokanOperations.Cleanup)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})")),
            operations
                .Setup(d => d.CloseFile(path.AsSpan(), It.Is<DokanFileInfo>(i => i.IsDirectory)))
                .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                    => Trace($"{nameof(IDokanOperations.CloseFile)}[{Interlocked.Decrement(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"))
        };
    }

    internal void PermitCreateDirectory(string path, NativeFileAccess access = ReadDirectoryAccess, FileShare share = FileShare.ReadWrite, FileMode mode = FileMode.CreateNew, FileOptions options = FileOptions.None, FileAttributes attributes = FileAttributes.Normal)
    {
        SetupCreateDirectory(path, access, share, mode, options, attributes);

        PermitGetFileInformation(path, FileAttributes.Directory);
    }

    internal void ExpectCreateDirectory(string path, NativeFileAccess access = ReadDirectoryAccess, FileShare share = FileShare.ReadWrite, FileMode mode = FileMode.CreateNew, FileOptions options = FileOptions.None, FileAttributes attributes = FileAttributes.Normal)
    {
        Array.ForEach(SetupCreateDirectory(path, access, share, mode, options, attributes), i => i.Verifiable());

        PermitGetFileInformation(path, FileAttributes.Directory);
    }

    internal void ExpectCreateDirectoryToFail(string path, NtStatus result)
    {
        if (result == DokanResult.Success)
        {
            throw new ArgumentException($"{DokanResult.Success} not supported", nameof(result));
        }

        operations
            .Setup(d => d.CreateFile(path.AsSpan(), ReadDirectoryAccess, FileShare.ReadWrite, FileMode.CreateNew, It.IsAny<FileOptions>(), It.IsAny<FileAttributes>(), It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(result)
            .Callback((ReadOnlySpan<char> fileName, FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CreateFile)}[{Interlocked.Increment(ref pendingFiles)}] **{result}** (\"{fileName}\", [{access}], [{share}], {mode}, [{options}], [{attributes}], {info.Log()})"))
            .Verifiable();

        ExpectCloseFile(path, isDirectory: true);
        ExpectCloseFile(path);
    }

    internal void ExpectDeleteDirectory(string path)
    {
        operations
            .Setup(d => d.DeleteDirectory(path.AsSpan(), It.Is<DokanFileInfo>(i => i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.DeleteDirectory)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"))
            .Verifiable();
    }

    private IVerifies SetupCreateFile(string path, NativeFileAccess access, FileShare share, FileMode mode, FileOptions options = FileOptions.None, FileAttributes attributes = default, object context = null, bool isDirectory = false)
    {
        return operations
            .Setup(d => d.CreateFile(path.AsSpan(), FileAccessUtils.MapSpecificToGenericAccess(access), share, mode, options, attributes, It.Is<DokanFileInfo>(i => i.IsDirectory == isDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, NativeFileAccess _access, FileShare _share, FileMode _mode, FileOptions _options, FileAttributes _attributes, DokanFileInfo info)
                =>
                {
                    info.Context = context;
                    Trace($"{nameof(IDokanOperations.CreateFile)}[{Interlocked.Increment(ref pendingFiles)}] (\"{fileName}\", [{_access}], [{_share}], {_mode}, [{_options}], [{_attributes}], {info.Log()})");
                });
    }

    internal void PermitCreateFile(string path, NativeFileAccess access, FileShare share, FileMode mode, FileOptions options = FileOptions.None, FileAttributes attributes = default, object context = null, bool isDirectory = false) => SetupCreateFile(path, access, share, mode, options, attributes, context, isDirectory);

    internal void ExpectCreateFile(string path, NativeFileAccess access, FileShare share, FileMode mode, FileOptions options = FileOptions.None, FileAttributes attributes = default, object context = null, bool isDirectory = false, bool deleteOnClose = false)
    {
        SetupCreateFile(path, access, share, mode, options, attributes, context, isDirectory)
            .Verifiable();

        PermitGetFileInformation(path, FileAttributes.Normal);
        ExpectCleanupFile(path, context, isDirectory, deleteOnClose);
    }

    internal void ExpectCreateFileWithoutCleanup(string path, NativeFileAccess access, FileShare share, FileMode mode, FileOptions options = FileOptions.None, FileAttributes attributes = default, object context = null, bool isDirectory = false)
    {
        operations
            .Setup(d => d.CreateFile(path.AsSpan(), FileAccessUtils.MapSpecificToGenericAccess(access), share, mode, options, attributes, It.Is<DokanFileInfo>(i => i.IsDirectory == isDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAccess _access, FileShare _share, FileMode _mode, FileOptions _options, FileAttributes _attributes, DokanFileInfo info)
                =>
                {
                    info.Context = context;
                    Trace($"{nameof(IDokanOperations.CreateFile)}-NoCleanup[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_access}], [{_share}], {_mode}, [{_options}], [{_attributes}], {info.Log()})");
                })
            .Verifiable();
    }

    internal void ExpectCreateFileToFail(string path, NtStatus result, bool closeFile = false)
    {
        if (result == DokanResult.Success)
        {
            throw new ArgumentException($"{DokanResult.Success} not supported", nameof(result));
        }

        operations
            .Setup(d => d.CreateFile(path.AsSpan(), It.IsAny<FileAccess>(), It.IsAny<FileShare>(), It.IsAny<FileMode>(), It.IsAny<FileOptions>(), It.IsAny<FileAttributes>(), It.IsAny<DokanFileInfo>()))
            .Returns(result)
            .Callback((ReadOnlySpan<char> fileName, FileAccess _access, FileShare _share, FileMode _mode, FileOptions options, FileAttributes _attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.CreateFile)}[{(closeFile ? Interlocked.Increment(ref pendingFiles) : Interlocked.Read(ref pendingFiles))}] **{result}** (\"{fileName}\", [{_access}], [{_share}], {_mode}, [{options}], [{_attributes}], {info.Log()})"))
            .Verifiable();

        if (closeFile)
        {
            ExpectCloseFile(path);
        }
    }

    internal void ExpectCleanupFile(string path, object context = null, bool isDirectory = false, bool deleteOnClose = false)
    {
        operations
            .Setup(d => d.Cleanup(path.AsSpan(), It.Is<DokanFileInfo>(i => i.Context == context && i.IsDirectory == isDirectory && i.DeleteOnClose == deleteOnClose)))
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.Cleanup)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"))
            .Verifiable();

        ExpectCloseFile(path, context, isDirectory, deleteOnClose);
    }

    internal void ExpectCloseFile(string path, object context = null, bool isDirectory = false, bool deleteOnClose = false)
    {
        operations
            .Setup(d => d.CloseFile(path.AsSpan(), It.Is<DokanFileInfo>(i => i.Context == context && i.IsDirectory == isDirectory && i.DeleteOnClose == deleteOnClose)))
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                =>
                {
                    Trace($"{nameof(IDokanOperations.CloseFile)}[{(isDirectory ? Interlocked.Read(ref pendingFiles) : Interlocked.Decrement(ref pendingFiles))}] (\"{fileName}\", {info.Log()})");
                    info.Context = null;
                })
            .Verifiable();
    }

    internal void ExpectFlushFileBuffers(string path)
    {
        operations
            .Setup(d => d.FlushFileBuffers(path.AsSpan(), It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FlushFileBuffers)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectLockUnlockFile(string path, long offset, long length)
    {
        operations
            .Setup(d => d.LockFile(path.AsSpan(), offset, length, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long _offset, long _length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.LockFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {_offset}, {_length}, {info.Log()})"))
            .Verifiable();
        operations
            .Setup(d => d.UnlockFile(path.AsSpan(), offset, length, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long _offset, long _length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.UnlockFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {_offset}, {_length}, {info.Log()})"))
            .Verifiable();
    }

    internal void PermitProbeFile(string path, byte[] buffer, int probeBufferSize = PROBE_BUFFER_SIZE)
    {
        operations
            .Setup(d => d.ReadFile(path.AsSpan(), It.Is<byte[]>(b => b.Length == probeBufferSize), out probeBufferSize, 0, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesRead, long _offset, DokanFileInfo info)
                =>
                {
                    Array.ConstrainedCopy(buffer, 0, _buffer, 0, Math.Min(probeBufferSize, buffer.Length));
                    Trace($"ProbeFile[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], {_buffer.SequenceEqual(buffer)}, out {_bytesRead}, {_offset}, {info.Log()})");
                });
    }

    internal void ExpectReadFile(string path, byte[] buffer, int bytesRead, object context = null,
        bool synchronousIo = true)
    {
        operations
            .Setup(d => d.ReadFile(path.AsSpan(), It.IsAny<byte[]>(), out bytesRead, 0, It.Is<DokanFileInfo>(i => i.Context == context && !i.IsDirectory && i.SynchronousIo == synchronousIo)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesRead, long _offset, DokanFileInfo info)
                =>
                {
                    Array.ConstrainedCopy(buffer, 0, _buffer, 0, Math.Min(bytesRead, _buffer.Length));
                    Trace($"{nameof(IDokanOperations.ReadFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], {_buffer.SequenceEqual(buffer)}, out {_bytesRead}, {_offset}, {info.Log()})");
                })
            .Verifiable();
    }

    internal void ExpectReadFileWithDelay(string path, byte[] buffer, int bytesRead, TimeSpan delay)
    {
        operations
            .Setup(d => d.ReadFile(path.AsSpan(), It.IsAny<byte[]>(), out bytesRead, 0, It.Is<DokanFileInfo>(i => !i.IsDirectory && i.SynchronousIo)))
            .Callback(() => Thread.Sleep(delay))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesRead, long _offset, DokanFileInfo info)
                =>
                {
                    Array.ConstrainedCopy(buffer, 0, _buffer, 0, Math.Min(bytesRead, _buffer.Length));
                    Trace($"{nameof(IDokanOperations.ReadFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], {_buffer.SequenceEqual(buffer)}, out {_bytesRead}, {_offset}, {info.Log()})");
                })
            .Verifiable();
    }

    internal void ExpectReadFileInChunks(string path, byte[] buffer, int chunkSize, object context = null, bool synchronousIo = true)
    {
        var offsets = new int[NumberOfChunks(chunkSize, buffer.Length)];
        for (int offset = 0, index = 0; offset < buffer.Length; offset += chunkSize, ++index)
        {
            offsets[index] = offset;
            var bytesRemaining = buffer.Length - offset;
            var bytesRead = Math.Min(chunkSize, bytesRemaining);
            operations
                .Setup(d => d.ReadFile(path.AsSpan(), It.Is<byte[]>(b => b.Length == chunkSize || b.Length == bytesRemaining), out bytesRead, offsets[index],
                            It.Is<DokanFileInfo>(i => i.Context == context && !i.IsDirectory && i.SynchronousIo == synchronousIo)))
                .Returns(DokanResult.Success)
                .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesRead, long _offset, DokanFileInfo info)
                    =>
                    {
                        Array.ConstrainedCopy(buffer, (int)_offset, _buffer, 0, _bytesRead);
                        Trace($"{nameof(IDokanOperations.ReadFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], {_buffer.Take(_bytesRead).SequenceEqual(buffer.Skip((int)_offset).Take(_bytesRead))}, out {_bytesRead}, {_offset}, {info.Log()})");
                    })
                .Verifiable();
        }
    }

    internal void ExpectWriteFile(string path, byte[] buffer, int bytesWritten, object context = null, bool synchronousIo = true)
    {
        operations
            .Setup(d => d.WriteFile(path.AsSpan(), It.Is<byte[]>(b => b.SequenceEqual(buffer)), out bytesWritten, 0, It.Is<DokanFileInfo>(i => i.Context == context && !i.IsDirectory && i.SynchronousIo == synchronousIo)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesWritten, long offset, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.WriteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], out {_bytesWritten}, {offset}, {info.Log()})"))
            .Verifiable();
    }

    private static bool IsSequenceEqual(IEnumerable<byte> b, IEnumerable<byte> buffer)
    {
        var result = b.SequenceEqual(buffer);
        return result;
    }

    internal void ExpectWriteFileWithDelay(string path, byte[] buffer, int bytesWritten, TimeSpan delay)
    {
        operations
            .Setup(d => d.WriteFile(path.AsSpan(), It.Is<byte[]>(b => IsSequenceEqual(b, buffer) /*b.SequenceEqual(buffer)*/), out bytesWritten, 0, It.Is<DokanFileInfo>(i => !i.IsDirectory && i.SynchronousIo)))
            .Callback(() => Thread.Sleep(delay))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesWritten, long offset, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.WriteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], out {_bytesWritten}, {offset}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectWriteFileInChunks(string path, byte[] buffer, int chunkSize, object context = null, bool synchronousIo = true)
    {
        var offsets = new int[NumberOfChunks(chunkSize, buffer.Length)];
        for (int offset = 0, index = 0; offset < buffer.Length; offset += chunkSize, ++index)
        {
            offsets[index] = offset;
            var bytesWritten = Math.Min(chunkSize, buffer.Length - offset);
            var chunk = buffer.Skip(offset).Take(bytesWritten);
            operations
                .Setup(d => d.WriteFile(path.AsSpan(), It.Is<byte[]>(b => IsSequenceEqual(b, chunk) /*b.SequenceEqual(chunk)*/), out bytesWritten, offsets[index],
                            It.Is<DokanFileInfo>(i => i.Context == context && !i.IsDirectory && i.SynchronousIo == synchronousIo)))
                .Returns(DokanResult.Success)
                .Callback((ReadOnlySpan<char> fileName, byte[] _buffer, int _bytesWritten, long _offset, DokanFileInfo info)
                    => Trace($"{nameof(IDokanOperations.WriteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_buffer.Length}], out {_bytesWritten}, {_offset}, {info.Log()})"))
                .Verifiable();
        }
    }

    internal void ExpectDeleteFile(string path)
    {
        operations
            .Setup(d => d.DeleteFile(path.AsSpan(), It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.DeleteFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectMoveFile(string path, string destinationPath, bool replace)
    {
        operations
            .Setup(d => d.MoveFile(path.AsSpan(), destinationPath.AsSpan(), replace, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((string oldName, string newName, bool _replace, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.MoveFile)}[{Interlocked.Add(ref pendingFiles, 2)}] (\"{oldName}\", \"{newName}\", {_replace}, {info.Log()})"))
            .Verifiable();

        ExpectCleanupFile(destinationPath);
    }

    internal void ExpectMoveFileToFail(string path, string destinationPath, bool replace, NtStatus result)
    {
        operations
            .Setup(d => d.MoveFile(path.AsSpan(), destinationPath.AsSpan(), replace, It.IsAny<DokanFileInfo>()))
            .Returns(result)
            .Callback((string oldName, string newName, bool _replace, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.MoveFile)}[{Interlocked.Add(ref pendingFiles, 2)}] **{result}** (\"{oldName}\", \"{newName}\", {_replace}, {info.Log()})"))
            .Verifiable();

        ExpectCleanupFile(destinationPath, isDirectory: true);
        ExpectCleanupFile(destinationPath);
        ExpectCloseFile(path);
    }

    internal void ExpectSetAllocationSize(string path, long length)
    {
        operations
            .Setup(d => d.SetAllocationSize(path.AsSpan(), length, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long _length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetAllocationSize)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {_length}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectSetEndOfFile(string path, long length)
    {
        operations
            .Setup(d => d.SetEndOfFile(path.AsSpan(), length, It.Is<DokanFileInfo>(i => !i.IsDirectory)))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, long _length, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetEndOfFile)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {_length}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectSetFileAttributes(string path, FileAttributes attributes)
    {
        operations
            .Setup(d => d.SetFileAttributes(path.AsSpan(), attributes, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileAttributes _attributes, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileAttributes)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", [{_attributes}], {info.Log()})"));
    }

    internal void ExpectSetFileTime(string path)
    {
        operations
            .Setup(d => d.SetFileTime(path.AsSpan(), It.IsAny<DateTime?>(), It.IsAny<DateTime?>(), It.IsAny<DateTime?>(), It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileTime)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {creationTime}, {lastAccessTime}, {lastWriteTime}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectGetFileSecurity(string path, FileSystemSecurity security, AccessControlSections access = AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group)
    {
        operations
            .Setup(d => d.GetFileSecurity(path.AsSpan(), out security, access, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileSystemSecurity _security, AccessControlSections _access, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.GetFileSecurity)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out {_security.AsString()}, {_access}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectSetFileSecurity(string path, FileSystemSecurity _2)
    {
        operations
            //.Setup(d => d.SetFileSecurity(path, security, AccessControlSections.Access, It.IsAny<DokanFileInfo>()))
            .Setup(d => d.SetFileSecurity(path.AsSpan(), It.IsAny<FileSystemSecurity>(), AccessControlSections.Access, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.Success)
            .Callback((ReadOnlySpan<char> fileName, FileSystemSecurity _security, AccessControlSections access, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.SetFileSecurity)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", {_security.AsString()}, {access}, {info.Log()})"))
            .Verifiable();
    }

    internal void ExpectFindStreams(string path, IEnumerable<FindFileInformation> streamNames)
    {
        long streamSize = streamNames.Count();
        operations
            .Setup(d => d.FindStreams(path.AsSpan(), out streamNames, It.IsAny<DokanFileInfo>()))
            .Returns(DokanResult.NotImplemented)
            .Callback((ReadOnlySpan<char> fileName, IList<FindFileInformation> _streamNames, DokanFileInfo info)
                => Trace($"{nameof(IDokanOperations.FindStreams)}[{Interlocked.Read(ref pendingFiles)}] (\"{fileName}\", out [{_streamNames.Count}], {info.Log()})"))
            .Verifiable();
    }

    private void PrepareVerify()
    {
        // For single-core environments, allow other threads to complete
        Thread.Yield();

        if (Interlocked.Read(ref pendingFiles) < 0)
        {
            throw new InvalidOperationException("Negative pending files count");
        }

        for (var i = 1; Interlocked.Read(ref pendingFiles) > 0; ++i)
        {
            if (i > 5)
            {
                throw new TimeoutException("Cleanup wait cycles exceeded");
            }

            Trace($"Waiting for closure (#{i})");
            Thread.Sleep(1);
        }
    }

    internal void Verify()
    {
        PrepareVerify();

        operations.Verify();
    }

    internal void VerifyContextReadInvocations(ReadOnlySpan<char> fileName, int count)
    {
        PrepareVerify();

        operations.Verify();
        operations.Verify(d => d.ReadFile(fileName.AsSpan(), It.IsAny<byte[]>(), out var bytesRead, It.IsAny<long>(), It.IsAny<DokanFileInfo>()), Times.Exactly(count));
    }

    internal void VerifyContextWriteInvocations(ReadOnlySpan<char> fileName, int count)
    {
        PrepareVerify();

        operations.Verify();
        operations.Verify(d => d.WriteFile(fileName.AsSpan(), It.IsAny<byte[]>(), out var bytesRead, It.IsAny<long>(), It.IsAny<DokanFileInfo>()), Times.Exactly(count));
    }
}