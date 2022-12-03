using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using DokanNet;
using Microsoft.Win32;
using NativeFileAccess = DokanNet.NativeFileAccess;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0057 // Use range operator

namespace RegistryFS;

internal class RFS : IDokanOperations
{
    #region DokanOperations member

    private readonly Dictionary<string, RegistryKey> TopDirectory;

    public RFS()
    {
        TopDirectory = new Dictionary<string, RegistryKey>
        {
            ["ClassesRoot"] = Registry.ClassesRoot,
            ["CurrentUser"] = Registry.CurrentUser,
            ["CurrentConfig"] = Registry.CurrentConfig,
            ["LocalMachine"] = Registry.LocalMachine,
            ["Users"] = Registry.Users
        };
    }

    public void Cleanup(ReadOnlySpan<char> filename, ref DokanFileInfo info)
    {
    }

    public void CloseFile(ReadOnlySpan<char> filename, ref DokanFileInfo info)
    {
    }

    public NtStatus CreateFile(
        ReadOnlySpan<char> filename,
        NativeFileAccess access,
        FileShare share,
        FileMode mode,
        FileOptions options,
        FileAttributes attributes,
        ref DokanFileInfo info)
    {
        if (info.IsDirectory && mode == FileMode.CreateNew)
        {
            return DokanResult.AccessDenied;
        }

        return DokanResult.Success;
    }

    public NtStatus DeleteDirectory(ReadOnlySpan<char> filename, in DokanFileInfo info) => DokanResult.Error;

    public NtStatus DeleteFile(ReadOnlySpan<char> filename, in DokanFileInfo info) => DokanResult.Error;

    private RegistryKey GetRegistoryEntry(ReadOnlySpan<char> name)
    {
        var top = name.Slice(1).IndexOf('\\');
        if (top < 0)
        {
            top = name.Length - 1;
        }

        var topname = name.Slice(1, top).ToString();
        var sub = name.Slice(1).IndexOf('\\');

        if (TopDirectory.TryGetValue(topname, out var subkey))
        {
            if (sub == -1)
            {
                return subkey;
            }
            else
            {
                var subKeyPath = name.Slice(sub + 2).ToString();
                return subkey.OpenSubKey(subKeyPath);
            }
        }

        return null;
    }

    public NtStatus FlushFileBuffers(
        ReadOnlySpan<char> filename,
        in DokanFileInfo info) => DokanResult.Error;

    public NtStatus FindFiles(
        ReadOnlySpan<char> filename,
        out IEnumerable<FindFileInformation> files,
        in DokanFileInfo info)
    {
        if (filename.Equals("\\".AsSpan(), StringComparison.Ordinal))
        {
            files = TopDirectory.Keys.Select(name => new FindFileInformation
            {
                FileName = name.AsMemory(),
                Attributes = FileAttributes.Directory,
                LastAccessTime = DateTime.Now,
                LastWriteTime = null,
                CreationTime = null
            });
            return DokanResult.Success;
        }
        else
        {
            var key = GetRegistoryEntry(filename);
            
            if (key == null)
            {
                files = null;
                return DokanResult.Error;
            }

            files = key
                .GetSubKeyNames()
                .Select(name => new FindFileInformation
                {
                    FileName = name.AsMemory(),
                    Attributes = FileAttributes.Directory,
                    LastAccessTime = DateTime.Now,
                    LastWriteTime = null,
                    CreationTime = null
                })
                .Concat(key
                .GetValueNames()
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => new FindFileInformation
                {
                    FileName = name.AsMemory(),
                    Attributes = FileAttributes.Normal,
                    LastAccessTime = DateTime.Now,
                    LastWriteTime = null,
                    CreationTime = null
                }));

            return DokanResult.Success;
        }
    }

    public NtStatus GetFileInformation(
        ReadOnlySpan<char> filename,
        out ByHandleFileInformation fileinfo,
        in DokanFileInfo info)
    {
        fileinfo = new ByHandleFileInformation();

        if (filename.Equals("\\".AsSpan(), StringComparison.Ordinal))
        {
            fileinfo.Attributes = FileAttributes.Directory;
            fileinfo.LastAccessTime = DateTime.Now;
            fileinfo.LastWriteTime = null;
            fileinfo.CreationTime = null;

            return DokanResult.Success;
        }

        var key = GetRegistoryEntry(filename);
        if (key == null)
        {
            return DokanResult.Error;
        }

        fileinfo.Attributes = FileAttributes.Directory;
        fileinfo.LastAccessTime = DateTime.Now;
        fileinfo.LastWriteTime = null;
        fileinfo.CreationTime = null;

        return DokanResult.Success;
    }

    public NtStatus LockFile(
        ReadOnlySpan<char> filename,
        long offset,
        long length,
        in DokanFileInfo info) => DokanResult.Success;

    public NtStatus MoveFile(
        ReadOnlySpan<char> filename,
        ReadOnlySpan<char> newname,
        bool replace,
        ref DokanFileInfo info) => DokanResult.Error;

    public NtStatus ReadFile(
        ReadOnlySpan<char> filename,
        Span<byte> buffer,
        out int readBytes,
        long offset,
        in DokanFileInfo info)
    {
        readBytes = 0;
        return DokanResult.Error;
    }

    public NtStatus SetEndOfFile(ReadOnlySpan<char> filename, long length, in DokanFileInfo info) => DokanResult.Error;

    public NtStatus SetAllocationSize(ReadOnlySpan<char> filename, long length, in DokanFileInfo info) => DokanResult.Error;

    public NtStatus SetFileAttributes(
        ReadOnlySpan<char> filename,
        FileAttributes attr,
        in DokanFileInfo info) => DokanResult.Error;

    public NtStatus SetFileTime(
        ReadOnlySpan<char> filename,
        DateTime? ctime,
        DateTime? atime,
        DateTime? mtime,
        in DokanFileInfo info) => DokanResult.Error;

    public NtStatus UnlockFile(ReadOnlySpan<char> filename, long offset, long length, in DokanFileInfo info) => DokanResult.Success;

    public NtStatus Mounted(ReadOnlySpan<char> mountPoint, in DokanFileInfo info) => DokanResult.Success;

    public NtStatus Unmounted(in DokanFileInfo info) => DokanResult.Success;

    public NtStatus GetDiskFreeSpace(
        out long freeBytesAvailable,
        out long totalBytes,
        out long totalFreeBytes,
        in DokanFileInfo info)
    {
        freeBytesAvailable = 512 * 1024 * 1024;
        totalBytes = 1024 * 1024 * 1024;
        totalFreeBytes = 512 * 1024 * 1024;
        return DokanResult.Success;
    }

    public NtStatus WriteFile(
        ReadOnlySpan<char> filename,
        ReadOnlySpan<byte> buffer,
        out int writtenBytes,
        long offset,
        in DokanFileInfo info)
    {
        writtenBytes = 0;
        return DokanResult.Error;
    }

    public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features,
        out string fileSystemName, out uint maximumComponentLength, ref uint volumeSerialNumber, in DokanFileInfo info)
    {
        volumeLabel = "RFS";
        features = FileSystemFeatures.None;
        fileSystemName = string.Empty;
        maximumComponentLength = 256;
        return DokanResult.Error;
    }

    public NtStatus GetFileSecurity(ReadOnlySpan<char> fileName, out FileSystemSecurity security, AccessControlSections sections,
        in DokanFileInfo info)
    {
        security = null;
        return DokanResult.Error;
    }

    public NtStatus SetFileSecurity(ReadOnlySpan<char> fileName, FileSystemSecurity security, AccessControlSections sections,
        in DokanFileInfo info) => DokanResult.Error;

    public NtStatus EnumerateNamedStreams(string _1, IntPtr _2, out string streamName,
        out long streamSize, ref DokanFileInfo _5)
    {
        streamName = string.Empty;
        streamSize = 0;
        return DokanResult.NotImplemented;
    }

    public NtStatus FindStreams(ReadOnlySpan<char> fileName, out IEnumerable<FindFileInformation> streams, in DokanFileInfo info)
    {
        streams = FindFileInformation.Empty;
        return DokanResult.NotImplemented;
    }

    public NtStatus FindFilesWithPattern(ReadOnlySpan<char> fileName, ReadOnlySpan<char> searchPattern, out IEnumerable<FindFileInformation> files,
        in DokanFileInfo info)
    {
        files = FindFileInformation.Empty;
        return DokanResult.NotImplemented;
    }

    #endregion DokanOperations member
}

internal class Program
{
    private static void Main()
    {
        try
        {
            var rfs = new RFS();
            Dokan.Init();
            rfs.Mount("r:\\", DokanOptions.DebugMode | DokanOptions.StderrOutput);
            Dokan.Shutdown();
            Console.WriteLine(@"Success");
        }
        catch (DokanException ex)
        {
            Console.WriteLine(@"Error: " + ex.Message);
        }
    }
}
