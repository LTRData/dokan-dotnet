using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using DokanNet;
using DokanNet.Logging;
using static DokanNet.FormatProviders;
using NativeFileAccess = DokanNet.NativeFileAccess;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0022 // Use expression body for methods

namespace DokanNetMirror;

internal class Mirror :
#if NETCOREAPP || NETSTANDARD2_1_OR_GREATER
        IDokanOperationsUnsafe
#else
        IDokanOperations
#endif
{
    private readonly string path;

    private const NativeFileAccess DataAccess = NativeFileAccess.ReadData | NativeFileAccess.WriteData | NativeFileAccess.AppendData |
                                          NativeFileAccess.Execute |
                                          NativeFileAccess.GenericExecute | NativeFileAccess.GenericWrite |
                                          NativeFileAccess.GenericRead;

    private const NativeFileAccess DataWriteAccess = NativeFileAccess.WriteData | NativeFileAccess.AppendData |
                                               NativeFileAccess.Delete |
                                               NativeFileAccess.GenericWrite;

    private readonly ConsoleLogger logger = new("[Mirror] ");

    public Mirror(string path)
    {
        if (!Directory.Exists(path))
        {
            throw new ArgumentException(nameof(path));
        }

        this.path = path;
    }

    protected string GetPath(string fileName) => path + fileName;

    protected NtStatus Trace(string method, string fileName, IDokanFileInfo info, NtStatus result,
        params object[] parameters)
    {
#if DEBUG
        var extraParameters = parameters != null && parameters.Length > 0
            ? ", " + string.Join(", ", parameters.Select(x => string.Format(DefaultFormatProvider, "{0}", x)))
            : string.Empty;

        logger.Debug(DokanFormat($"{method}('{fileName}', {info}{extraParameters}) -> {result}"));
#endif

        return result;
    }

    private NtStatus Trace(string method, string fileName, IDokanFileInfo info,
        NativeFileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes,
        NtStatus result)
    {
#if DEBUG
        logger.Debug(
            DokanFormat(
                $"{method}('{fileName}', {info}, [{access}], [{share}], [{mode}], [{options}], [{attributes}]) -> {result}"));
#endif

        return result;
    }

    #region Implementation of IDokanOperations

    public NtStatus CreateFile(string fileName, NativeFileAccess access, FileShare share, FileMode mode,
        FileOptions options, FileAttributes attributes, IDokanFileInfo info)
    {
        var result = DokanResult.Success;
        var filePath = GetPath(fileName);

        if (info.IsDirectory)
        {
            try
            {
                switch (mode)
                {
                    case FileMode.Open:
                        if (!Directory.Exists(filePath))
                        {
                            try
                            {
                                if (!File.GetAttributes(filePath).HasFlag(FileAttributes.Directory))
                                {
                                    return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                        attributes, DokanResult.NotADirectory);
                                }
                            }
                            catch (Exception)
                            {
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.FileNotFound);
                            }
                            return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                attributes, DokanResult.PathNotFound);
                        }

                        new DirectoryInfo(filePath).EnumerateFileSystemInfos().Any();
                        // you can't list the directory
                        break;

                    case FileMode.CreateNew:
                        if (Directory.Exists(filePath))
                        {
                            return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                attributes, DokanResult.FileExists);
                        }

                        try
                        {
                            File.GetAttributes(filePath).HasFlag(FileAttributes.Directory);
                            return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                attributes, DokanResult.AlreadyExists);
                        }
                        catch (IOException)
                        {
                        }

                        Directory.CreateDirectory(GetPath(fileName));
                        break;
                }
            }
            catch (UnauthorizedAccessException)
            {
                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                    DokanResult.AccessDenied);
            }
        }
        else
        {
            var pathExists = true;
            var pathIsDirectory = false;

            var readWriteAttributes = (access & DataAccess) == 0;
            var readAccess = (access & DataWriteAccess) == 0;

            try
            {
                pathExists = (Directory.Exists(filePath) || File.Exists(filePath));
                pathIsDirectory = pathExists && File.GetAttributes(filePath).HasFlag(FileAttributes.Directory);
            }
            catch (IOException)
            {
            }

            switch (mode)
            {
                case FileMode.Open:

                    if (pathExists)
                    {
                        // check if driver only wants to read attributes, security info, or open directory
                        if (readWriteAttributes || pathIsDirectory)
                        {
                            if (pathIsDirectory && (access & NativeFileAccess.Delete) == NativeFileAccess.Delete
                                && (access & NativeFileAccess.Synchronize) != NativeFileAccess.Synchronize)
                            {
                                //It is a DeleteFile request on a directory
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.AccessDenied);
                            }

                            info.IsDirectory = pathIsDirectory;
                            info.Context = new object();
                            // must set it to something if you return DokanError.Success

                            return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                attributes, DokanResult.Success);
                        }
                    }
                    else
                    {
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.FileNotFound);
                    }
                    break;

                case FileMode.CreateNew:
                    if (pathExists)
                    {
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.FileExists);
                    }

                    break;

                case FileMode.Truncate:
                    if (!pathExists)
                    {
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.FileNotFound);
                    }

                    break;
            }

            try
            {
                info.Context = new FileStream(filePath, mode,
                    readAccess ? System.IO.FileAccess.Read : System.IO.FileAccess.ReadWrite, share, 4096, options);

                if (pathExists && (mode == FileMode.OpenOrCreate
                                   || mode == FileMode.Create))
                {
                    result = DokanResult.AlreadyExists;
                }

                var fileCreated = mode == FileMode.CreateNew || mode == FileMode.Create || (!pathExists && mode == FileMode.OpenOrCreate);
                if (fileCreated)
                {
                    var new_attributes = attributes;
                    new_attributes |= FileAttributes.Archive; // Files are always created as Archive
                                                              // FILE_ATTRIBUTE_NORMAL is override if any other attribute is set.
                    new_attributes &= ~FileAttributes.Normal;
                    File.SetAttributes(filePath, new_attributes);
                }
            }
            catch (UnauthorizedAccessException) // don't have access rights
            {
                if (info.Context is FileStream fileStream)
                {
                    // returning AccessDenied cleanup and close won't be called,
                    // so we have to take care of the stream now
                    fileStream.Dispose();
                    info.Context = null;
                }
                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                    DokanResult.AccessDenied);
            }
            catch (DirectoryNotFoundException)
            {
                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                    DokanResult.PathNotFound);
            }
            catch (Exception ex)
            {
                var hr = (uint)Marshal.GetHRForException(ex);
                switch (hr)
                {
                    case 0x80070020: //Sharing violation
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.SharingViolation);
                    default:
                        throw;
                }
            }
        }
        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
            result);
    }

    public void Cleanup(string fileName, IDokanFileInfo info)
    {
#if DEBUG
        if (info.Context != null)
        {
            Console.WriteLine(DokanFormat($"{nameof(Cleanup)}('{fileName}', {info} - entering"));
        }
#endif

        (info.Context as FileStream)?.Dispose();
        info.Context = null;

        if (info.DeleteOnClose)
        {
            if (info.IsDirectory)
            {
                Directory.Delete(GetPath(fileName));
            }
            else
            {
                File.Delete(GetPath(fileName));
            }
        }
        Trace(nameof(Cleanup), fileName, info, DokanResult.Success);
    }

    public void CloseFile(string fileName, IDokanFileInfo info)
    {
#if DEBUG
        if (info.Context != null)
        {
            Console.WriteLine(DokanFormat($"{nameof(CloseFile)}('{fileName}', {info} - entering"));
        }
#endif

        (info.Context as FileStream)?.Dispose();
        info.Context = null;
        Trace(nameof(CloseFile), fileName, info, DokanResult.Success);
        // could recreate cleanup code here but this is not called sometimes
    }

    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
    {
        if (info.Context == null) // memory mapped read
        {
            using var stream = new FileStream(GetPath(fileName), FileMode.Open, System.IO.FileAccess.Read);
            stream.Position = offset;
            bytesRead = stream.Read(buffer, 0, buffer.Length);
        }
        else // normal read
        {
            var stream = info.Context as FileStream;
            lock (stream) //Protect from overlapped read
            {
                stream.Position = offset;
                bytesRead = stream.Read(buffer, 0, buffer.Length);
            }
        }
        return Trace(nameof(ReadFile), fileName, info, DokanResult.Success, $"out {bytesRead}",
            offset.ToString(CultureInfo.InvariantCulture));
    }

#if NETCOREAPP || NETSTANDARD2_1_OR_GREATER
    public unsafe NtStatus ReadFile(string fileName, IntPtr buffer, uint bufferLength, out int bytesRead, long offset, IDokanFileInfo info)
    {
        if (info.Context == null) // memory mapped read
        {
            using var stream = new FileStream(GetPath(fileName), FileMode.Open, System.IO.FileAccess.Read);
            stream.Position = offset;
            bytesRead = stream.Read(new Span<byte>(buffer.ToPointer(), (int)bufferLength));
        }
        else // normal read
        {
            var stream = info.Context as FileStream;
            lock (stream) //Protect from overlapped read
            {
                stream.Position = offset;
                bytesRead = stream.Read(new Span<byte>(buffer.ToPointer(), (int)bufferLength));
            }
        }
        return Trace(nameof(ReadFile), fileName, info, DokanResult.Success, $"out {bytesRead}",
            offset.ToString(CultureInfo.InvariantCulture));
    }
#endif

    public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
    {
        var append = offset == -1;
        if (info.Context == null)
        {
            using var stream = new FileStream(GetPath(fileName), append ? FileMode.Append : FileMode.Open, System.IO.FileAccess.Write);
            if (!append) // Offset of -1 is an APPEND: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
            {
                stream.Position = offset;
            }
            stream.Write(buffer, 0, buffer.Length);
            bytesWritten = buffer.Length;
        }
        else
        {
            var stream = info.Context as FileStream;
            lock (stream) //Protect from overlapped write
            {
                if (append)
                {
                    if (stream.CanSeek)
                    {
                        stream.Seek(0, SeekOrigin.End);
                    }
                    else
                    {
                        bytesWritten = 0;
                        return Trace(nameof(WriteFile), fileName, info, DokanResult.Error, $"out {bytesWritten}",
                            offset.ToString(CultureInfo.InvariantCulture));
                    }
                }
                else
                {
                    stream.Position = offset;
                }
                stream.Write(buffer, 0, buffer.Length);
            }
            bytesWritten = buffer.Length;
        }
        return Trace(nameof(WriteFile), fileName, info, DokanResult.Success, $"out {bytesWritten}",
            offset.ToString(CultureInfo.InvariantCulture));
    }

#if NETCOREAPP || NETSTANDARD2_1_OR_GREATER
    public unsafe NtStatus WriteFile(string fileName, IntPtr buffer, uint bufferLength, out int bytesWritten, long offset, IDokanFileInfo info)
    {
        var append = offset == -1;
        if (info.Context == null)
        {
            using var stream = new FileStream(GetPath(fileName), append ? FileMode.Append : FileMode.Open, System.IO.FileAccess.Write);
            if (!append) // Offset of -1 is an APPEND: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
            {
                stream.Position = offset;
            }
            stream.Write(new ReadOnlySpan<byte>(buffer.ToPointer(), (int)bufferLength));
            bytesWritten = (int)bufferLength;
        }
        else
        {
            var stream = info.Context as FileStream;
            lock (stream) //Protect from overlapped write
            {
                if (append)
                {
                    if (stream.CanSeek)
                    {
                        stream.Seek(0, SeekOrigin.End);
                    }
                    else
                    {
                        bytesWritten = 0;
                        return Trace(nameof(WriteFile), fileName, info, DokanResult.Error, $"out {bytesWritten}",
                            offset.ToString(CultureInfo.InvariantCulture));
                    }
                }
                else
                {
                    stream.Position = offset;
                }
                stream.Write(new ReadOnlySpan<byte>(buffer.ToPointer(), (int)bufferLength));
            }
            bytesWritten = (int)bufferLength;
        }
        return Trace(nameof(WriteFile), fileName, info, DokanResult.Success, $"out {bytesWritten}",
            offset.ToString(CultureInfo.InvariantCulture));
    }
#endif

    public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info)
    {
        try
        {
            ((FileStream)(info.Context)).Flush();
            return Trace(nameof(FlushFileBuffers), fileName, info, DokanResult.Success);
        }
        catch (IOException)
        {
            return Trace(nameof(FlushFileBuffers), fileName, info, DokanResult.DiskFull);
        }
    }

    public NtStatus GetFileInformation(string fileName, out ByHandleFileInformation fileInfo, IDokanFileInfo info)
    {
        // may be called with info.Context == null, but usually it isn't
        var filePath = GetPath(fileName);
        FileSystemInfo finfo = new FileInfo(filePath);
        if (!finfo.Exists)
        {
            finfo = new DirectoryInfo(filePath);
        }

        fileInfo = new ByHandleFileInformation
        {
            Attributes = finfo.Attributes,
            CreationTime = finfo.CreationTime,
            LastAccessTime = finfo.LastAccessTime,
            LastWriteTime = finfo.LastWriteTime,
            Length = (finfo as FileInfo)?.Length ?? 0,
        };
        return Trace(nameof(GetFileInformation), fileName, info, DokanResult.Success);
    }

    public NtStatus FindFiles(string fileName, out IEnumerable<FindFileInformation> files, IDokanFileInfo info)
    {
        // This function is not called because FindFilesWithPattern is implemented
        // Return DokanResult.NotImplemented in FindFilesWithPattern to make FindFiles called
        files = FindFilesHelper(fileName, "*");

        return Trace(nameof(FindFiles), fileName, info, DokanResult.Success);
    }

    public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info)
    {
        try
        {
            // MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
            // because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
            if (attributes != 0)
            {
                File.SetAttributes(GetPath(fileName), attributes);
            }

            return Trace(nameof(SetFileAttributes), fileName, info, DokanResult.Success, attributes.ToString());
        }
        catch (UnauthorizedAccessException)
        {
            return Trace(nameof(SetFileAttributes), fileName, info, DokanResult.AccessDenied, attributes.ToString());
        }
        catch (FileNotFoundException)
        {
            return Trace(nameof(SetFileAttributes), fileName, info, DokanResult.FileNotFound, attributes.ToString());
        }
        catch (DirectoryNotFoundException)
        {
            return Trace(nameof(SetFileAttributes), fileName, info, DokanResult.PathNotFound, attributes.ToString());
        }
    }

    public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime,
        DateTime? lastWriteTime, IDokanFileInfo info)
    {
        try
        {
            if (info.Context is FileStream stream)
            {
                var ct = creationTime?.ToFileTime() ?? 0;
                var lat = lastAccessTime?.ToFileTime() ?? 0;
                var lwt = lastWriteTime?.ToFileTime() ?? 0;
                if (NativeMethods.SetFileTime(stream.SafeFileHandle, ref ct, ref lat, ref lwt))
                {
                    return DokanResult.Success;
                }

                throw Marshal.GetExceptionForHR(Marshal.GetLastWin32Error());
            }

            var filePath = GetPath(fileName);

            if (creationTime.HasValue)
            {
                File.SetCreationTime(filePath, creationTime.Value);
            }

            if (lastAccessTime.HasValue)
            {
                File.SetLastAccessTime(filePath, lastAccessTime.Value);
            }

            if (lastWriteTime.HasValue)
            {
                File.SetLastWriteTime(filePath, lastWriteTime.Value);
            }

            return Trace(nameof(SetFileTime), fileName, info, DokanResult.Success, creationTime, lastAccessTime,
                lastWriteTime);
        }
        catch (UnauthorizedAccessException)
        {
            return Trace(nameof(SetFileTime), fileName, info, DokanResult.AccessDenied, creationTime, lastAccessTime,
                lastWriteTime);
        }
        catch (FileNotFoundException)
        {
            return Trace(nameof(SetFileTime), fileName, info, DokanResult.FileNotFound, creationTime, lastAccessTime,
                lastWriteTime);
        }
    }

    public NtStatus DeleteFile(string fileName, IDokanFileInfo info)
    {
        var filePath = GetPath(fileName);

        if (Directory.Exists(filePath))
        {
            return Trace(nameof(DeleteFile), fileName, info, DokanResult.AccessDenied);
        }

        if (!File.Exists(filePath))
        {
            return Trace(nameof(DeleteFile), fileName, info, DokanResult.FileNotFound);
        }

        if (File.GetAttributes(filePath).HasFlag(FileAttributes.Directory))
        {
            return Trace(nameof(DeleteFile), fileName, info, DokanResult.AccessDenied);
        }

        return Trace(nameof(DeleteFile), fileName, info, DokanResult.Success);
        // we just check here if we could delete the file - the true deletion is in Cleanup
    }

    public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info)
    {
        return Trace(nameof(DeleteDirectory), fileName, info,
            Directory.EnumerateFileSystemEntries(GetPath(fileName)).Any()
                ? DokanResult.DirectoryNotEmpty
                : DokanResult.Success);
        // if dir is not empty it can't be deleted
    }

    public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
    {
        var oldpath = GetPath(oldName);
        var newpath = GetPath(newName);

        (info.Context as FileStream)?.Dispose();
        info.Context = null;

        var exist = info.IsDirectory ? Directory.Exists(newpath) : File.Exists(newpath);

        try
        {

            if (!exist)
            {
                info.Context = null;
                if (info.IsDirectory)
                {
                    Directory.Move(oldpath, newpath);
                }
                else
                {
                    File.Move(oldpath, newpath);
                }

                return Trace(nameof(MoveFile), oldName, info, DokanResult.Success, newName,
                    replace.ToString(CultureInfo.InvariantCulture));
            }
            else if (replace)
            {
                info.Context = null;

                if (info.IsDirectory) //Cannot replace directory destination - See MOVEFILE_REPLACE_EXISTING
                {
                    return Trace(nameof(MoveFile), oldName, info, DokanResult.AccessDenied, newName,
                        replace.ToString(CultureInfo.InvariantCulture));
                }

                File.Delete(newpath);
                File.Move(oldpath, newpath);
                return Trace(nameof(MoveFile), oldName, info, DokanResult.Success, newName,
                    replace.ToString(CultureInfo.InvariantCulture));
            }
        }
        catch (UnauthorizedAccessException)
        {
            return Trace(nameof(MoveFile), oldName, info, DokanResult.AccessDenied, newName,
                replace.ToString(CultureInfo.InvariantCulture));
        }
        return Trace(nameof(MoveFile), oldName, info, DokanResult.FileExists, newName,
            replace.ToString(CultureInfo.InvariantCulture));
    }

    public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info)
    {
        try
        {
            ((FileStream)(info.Context)).SetLength(length);
            return Trace(nameof(SetEndOfFile), fileName, info, DokanResult.Success,
                length.ToString(CultureInfo.InvariantCulture));
        }
        catch (IOException)
        {
            return Trace(nameof(SetEndOfFile), fileName, info, DokanResult.DiskFull,
                length.ToString(CultureInfo.InvariantCulture));
        }
    }

    public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info)
    {
        try
        {
            ((FileStream)info.Context).SetLength(length);
            return Trace(nameof(SetAllocationSize), fileName, info, DokanResult.Success,
                length.ToString(CultureInfo.InvariantCulture));
        }
        catch (IOException)
        {
            return Trace(nameof(SetAllocationSize), fileName, info, DokanResult.DiskFull,
                length.ToString(CultureInfo.InvariantCulture));
        }
    }

    public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info)
    {
        try
        {
            ((FileStream)info.Context).Lock(offset, length);
            return Trace(nameof(LockFile), fileName, info, DokanResult.Success,
                offset.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture));
        }
        catch (IOException)
        {
            return Trace(nameof(LockFile), fileName, info, DokanResult.AccessDenied,
                offset.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture));
        }
    }

    public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info)
    {
        try
        {
            ((FileStream)(info.Context)).Unlock(offset, length);
            return Trace(nameof(UnlockFile), fileName, info, DokanResult.Success,
                offset.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture));
        }
        catch (IOException)
        {
            return Trace(nameof(UnlockFile), fileName, info, DokanResult.AccessDenied,
                offset.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture));
        }
    }

    public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
    {
        var dinfo = DriveInfo.GetDrives().Single(di => string.Equals(di.RootDirectory.Name, Path.GetPathRoot(path + "\\"), StringComparison.OrdinalIgnoreCase));

        freeBytesAvailable = dinfo.TotalFreeSpace;
        totalNumberOfBytes = dinfo.TotalSize;
        totalNumberOfFreeBytes = dinfo.AvailableFreeSpace;
        return Trace(nameof(GetDiskFreeSpace), null, info, DokanResult.Success, $"out {freeBytesAvailable}",
            $"out {totalNumberOfBytes}", $"out {totalNumberOfFreeBytes}");
    }

    public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features,
        out string fileSystemName, out uint maximumComponentLength, ref uint volumeSerialNumber, IDokanFileInfo info)
    {
        volumeLabel = "DOKAN";
        fileSystemName = "NTFS";
        maximumComponentLength = 256;

        features = FileSystemFeatures.CasePreservedNames | FileSystemFeatures.CaseSensitiveSearch |
                   FileSystemFeatures.PersistentAcls | FileSystemFeatures.SupportsRemoteStorage |
                   FileSystemFeatures.UnicodeOnDisk;

        return Trace(nameof(GetVolumeInformation), null, info, DokanResult.Success, $"out {volumeLabel}",
            $"out {features}", $"out {fileSystemName}");
    }

    public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections,
        IDokanFileInfo info)
    {
        try
        {
            security = info.IsDirectory
                ? new DirectoryInfo(GetPath(fileName)).GetAccessControl() as FileSystemSecurity
                : new FileInfo(GetPath(fileName)).GetAccessControl();
            return Trace(nameof(GetFileSecurity), fileName, info, DokanResult.Success, sections.ToString());
        }
        catch (UnauthorizedAccessException)
        {
            security = null;
            return Trace(nameof(GetFileSecurity), fileName, info, DokanResult.AccessDenied, sections.ToString());
        }
    }

    public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections,
        IDokanFileInfo info)
    {
        try
        {
            if (info.IsDirectory)
            {
                new DirectoryInfo(GetPath(fileName)).SetAccessControl((DirectorySecurity)security);
            }
            else
            {
                new FileInfo(GetPath(fileName)).SetAccessControl((FileSecurity)security);
            }
            return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.Success, sections.ToString());
        }
        catch (UnauthorizedAccessException)
        {
            return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.AccessDenied, sections.ToString());
        }
    }

    public NtStatus Mounted(IDokanFileInfo info) => Trace(nameof(Mounted), null, info, DokanResult.Success);

    public NtStatus Unmounted(IDokanFileInfo info) => Trace(nameof(Unmounted), null, info, DokanResult.Success);

    public NtStatus FindStreams(string fileName, IntPtr enumContext, out string streamName, out long streamSize,
        IDokanFileInfo info)
    {
        streamName = string.Empty;
        streamSize = 0;
        return Trace(nameof(FindStreams), fileName, info, DokanResult.NotImplemented, enumContext.ToString(),
            $"out {streamName}", $"out {streamSize}");
    }

    public NtStatus FindStreams(string fileName, out IEnumerable<FindFileInformation> streams, IDokanFileInfo info)
    {
        streams = new FindFileInformation[0];
        return Trace(nameof(FindStreams), fileName, info, DokanResult.NotImplemented);
    }

    public IEnumerable<FindFileInformation> FindFilesHelper(string fileName, string searchPattern)
    {
        var files = new DirectoryInfo(GetPath(fileName))
            .EnumerateFileSystemInfos()
            .Where(finfo => DokanHelper.DokanIsNameInExpression(searchPattern, finfo.Name, true))
            .Select(finfo => new FindFileInformation
            {
                Attributes = finfo.Attributes,
                CreationTime = finfo.CreationTime,
                LastAccessTime = finfo.LastAccessTime,
                LastWriteTime = finfo.LastWriteTime,
                Length = (finfo as FileInfo)?.Length ?? 0,
                FileName = finfo.Name
            });

        return files;
    }

    public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IEnumerable<FindFileInformation> files,
        IDokanFileInfo info)
    {
        files = FindFilesHelper(fileName, searchPattern);

        return Trace(nameof(FindFilesWithPattern), fileName, info, DokanResult.Success);
    }

    #endregion Implementation of IDokanOperations
}
