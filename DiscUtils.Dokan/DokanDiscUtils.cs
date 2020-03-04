﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using DokanNet;
using DokanNet.Logging;
using NativeFileAccess = DokanNet.NativeFileAccess;
using static DokanNet.FormatProviders;
using System.Diagnostics;

namespace DiscUtils.Dokan
{
    public class DokanDiscUtils : IDokanOperations, IDisposable
    {
        public IFileSystem FileSystem { get; }

        public DokanDiscUtilsOptions Options { get; }


        private const NativeFileAccess DataAccess = NativeFileAccess.ReadData | NativeFileAccess.WriteData | NativeFileAccess.AppendData |
                                              NativeFileAccess.Execute |
                                              NativeFileAccess.GenericExecute | NativeFileAccess.GenericWrite |
                                              NativeFileAccess.GenericRead;

        private const NativeFileAccess DataWriteAccess = NativeFileAccess.WriteData | NativeFileAccess.AppendData |
                                                   NativeFileAccess.Delete |
                                                   NativeFileAccess.GenericWrite;

#if TRACE
        private readonly ConsoleLogger logger = new ConsoleLogger("[DokanDiscUtils] ");
#endif

        private readonly StringComparison _comparison = StringComparison.OrdinalIgnoreCase;

        public bool CaseSensitive { get; }

        public bool NamedStreams { get; }

        private NtStatus Trace(string method, string fileName, IDokanFileInfo info, NtStatus result,
            params object[] parameters)
        {
#if TRACE
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
#if TRACE
            logger.Debug(
                DokanFormat(
                    $"{method}('{fileName}', {info}, [{access}], [{share}], [{mode}], [{options}], [{attributes}]) -> {result}"));
#endif

            return result;
        }

        public DokanDiscUtils(IFileSystem filesystem, DokanDiscUtilsOptions options)
        {
            FileSystem = filesystem ?? throw new ArgumentNullException(nameof(filesystem));

            if (!filesystem.CanWrite)
            {
                options |= DokanDiscUtilsOptions.ForceReadOnly;
            }

            if (filesystem is IWindowsFileSystem)
            {
                NamedStreams = true;
            }
            else if (filesystem is IUnixFileSystem)
            {
                _comparison = StringComparison.Ordinal;
                CaseSensitive = true;
                NamedStreams = true;
            }

            Options = options;
        }

        #region Implementation of IDokanOperations

        private readonly List<KeyValuePair<string, string>> _transl = new List<KeyValuePair<string, string>>();

        private string TranslatePath(string path)
        {
            path = path.Trim('\\');

            if (string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            foreach (var transl in _transl)
            {
                if (path.Equals(transl.Key, _comparison))
                {
                    var newpath = transl.Value;
#if TRACE
                    Debug.WriteLine($"Using translation of '{path}' to '{newpath}'");
#endif

                    return newpath;
                }

                var dirpath = transl.Key + @"\";

                if (path.StartsWith(dirpath, _comparison))
                {
                    var newpath = transl.Value + path.Substring(transl.Key.Length);

                    _transl.Add(new KeyValuePair<string, string>(string.Intern(newpath), string.Intern(path)));

                    Debug.WriteLine($"DokanDiscUtils: Added parent directory based translation of '{path}' to '{newpath}'");

                    return newpath;
                }
            }

            return path;
        }

        private string SanitizePath(string path)
        {
            var newpath = TranslatePath(path);

            if (!ReferenceEquals(newpath, path))
            {
                return newpath;
            }

            newpath = path
                .Replace(":", "..")
                .Replace('?', '_')
                .Replace('*', '_')
                .Replace('"', '_')
                .Replace('\'', '_')
                .Replace('/', '\\')
                .Replace(',', '_')
                .Replace(';', '_');

            if (ReferenceEquals(newpath, path))
            {
                return path;
            }

            _transl.Add(new KeyValuePair<string, string>(string.Intern(newpath), string.Intern(path)));

            Debug.WriteLine($"DokanDiscUtils: Added translation of '{path}' to '{newpath}'");

            return newpath;
        }

        public NtStatus CreateFile(string fileName, NativeFileAccess access, FileShare share, FileMode mode,
            FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            var result = DokanResult.Success;

            fileName = TranslatePath(fileName);

            if (info.IsDirectory)
            {
                try
                {
                    switch (mode)
                    {
                        case FileMode.Open:

                            if (!FileSystem.DirectoryExists(fileName))
                            {
                                if (FileSystem.Exists(fileName))
                                    return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                        attributes, DokanResult.NotADirectory);

                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.PathNotFound);
                            }

                            break;

                        case FileMode.OpenOrCreate:
                        case FileMode.Create:
                            if (FileSystem.FileExists(fileName))
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.NotADirectory);

                            if (!FileSystem.DirectoryExists(fileName))
                                FileSystem.CreateDirectory(fileName);

                            break;

                        case FileMode.CreateNew:
                            if (FileSystem.FileExists(fileName))
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.FileExists);

                            if (FileSystem.DirectoryExists(fileName))
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.AlreadyExists);

                            FileSystem.CreateDirectory(fileName);
                            break;
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                        DokanResult.AccessDenied);
                }

                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                    result);
            }

            var pathExists = true;
            var pathIsDirectory = false;

            var readWriteAttributes = (access & DataAccess) == 0;
            var readAccess = (access & DataWriteAccess) == 0;

            try
            {
                pathExists = FileSystem.Exists(fileName);
                pathIsDirectory = FileSystem.DirectoryExists(fileName);
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
                                //It is a DeleteFile request on a directory
                                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options,
                                    attributes, DokanResult.AccessDenied);

                            info.IsDirectory = pathIsDirectory;

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
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.FileExists);
                    break;

                case FileMode.Truncate:
                    if (!pathExists)
                        return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                            DokanResult.FileNotFound);
                    break;
            }

            try
            {
                info.Context = FileSystem.OpenFile(fileName, mode,
                    readAccess ? System.IO.FileAccess.Read : System.IO.FileAccess.ReadWrite);

                if (pathExists && (mode == FileMode.OpenOrCreate
                                   || mode == FileMode.Create))
                    result = DokanResult.AlreadyExists; // Returned to caller for information, not error

                if (mode == FileMode.CreateNew || mode == FileMode.Create) //Files are always created as Archive
                {
                    attributes |= FileAttributes.Archive;
                    FileSystem.SetAttributes(fileName, attributes);
                }
            }
            catch (UnauthorizedAccessException) // don't have access rights
            {
                if (info.Context is Stream fileStream)
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
            when ((uint)ex.HResult == 0x80070020) //Sharing violation
            {
                return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                    DokanResult.SharingViolation);
            }

            return Trace(nameof(CreateFile), fileName, info, access, share, mode, options, attributes,
                result);
        }

        public void Cleanup(string fileName, IDokanFileInfo info)
        {
#if TRACE
            if (info.Context != null)
                Console.WriteLine(DokanFormat($"{nameof(Cleanup)}('{fileName}', {info} - entering"));
#endif

            (info.Context as IDisposable)?.Dispose();
            info.Context = null;

            if (info.DeleteOnClose)
            {
                fileName = TranslatePath(fileName);

                if (info.IsDirectory)
                {
                    FileSystem.DeleteDirectory(fileName);
                }
                else
                {
                    FileSystem.DeleteFile(fileName);
                }
            }
            Trace(nameof(Cleanup), fileName, info, DokanResult.Success);
        }

        public void CloseFile(string fileName, IDokanFileInfo info)
        {
#if TRACE
            if (info.Context != null)
                Console.WriteLine(DokanFormat($"{nameof(CloseFile)}('{fileName}', {info} - entering"));
#endif

            (info.Context as IDisposable)?.Dispose();
            info.Context = null;
            Trace(nameof(CloseFile), fileName, info, DokanResult.Success);
            // could recreate cleanup code here but this is not called sometimes
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            if (info.Context == null) // memory mapped read
            {
                fileName = TranslatePath(fileName);

                using var stream = FileSystem.OpenFile(fileName, FileMode.Open, System.IO.FileAccess.Read);
                stream.Position = offset;
                bytesRead = stream.Read(buffer, 0, buffer.Length);
            }
            else // normal read
            {
                var stream = info.Context as Stream;
                lock (stream) //Protect from overlapped read
                {
                    stream.Position = offset;
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                }
            }
            return Trace(nameof(ReadFile), fileName, info, DokanResult.Success, $"out {bytesRead}",
                offset.ToString(CultureInfo.InvariantCulture));
        }

        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            bytesWritten = 0;

            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(WriteFile), fileName, info, DokanResult.AccessDenied);

            if (info.Context == null)
            {
                fileName = TranslatePath(fileName);

                using var stream = FileSystem.OpenFile(fileName, FileMode.Open, System.IO.FileAccess.Write);
                stream.Position = offset;
                stream.Write(buffer, 0, buffer.Length);
                bytesWritten = buffer.Length;
            }
            else
            {
                var stream = info.Context as Stream;
                lock (stream) //Protect from overlapped write
                {
                    stream.Position = offset;
                    stream.Write(buffer, 0, buffer.Length);
                }
                bytesWritten = buffer.Length;
            }
            return Trace(nameof(WriteFile), fileName, info, DokanResult.Success, $"out {bytesWritten}",
                offset.ToString(CultureInfo.InvariantCulture));
        }

        public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info)
        {
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(FlushFileBuffers), fileName, info, DokanResult.AccessDenied);

            try
            {
                (info.Context as Stream)?.Flush();
                return Trace(nameof(FlushFileBuffers), fileName, info, DokanResult.Success);
            }
            catch (IOException)
            {
                return Trace(nameof(FlushFileBuffers), fileName, info, DokanResult.DiskFull);
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            fileName = TranslatePath(fileName);

            // may be called with info.Context == null, but usually it isn't
            var finfo = FileSystem.GetFileSystemInfo(fileName);

            fileInfo = new FileInformation
            {
                FileName = finfo.Name,
                Attributes = FilterAttributes(finfo.Attributes),
                CreationTime = finfo.CreationTime,
                LastAccessTime = finfo.LastAccessTime,
                LastWriteTime = finfo.LastWriteTime,
                Length = FileSystem.FileExists(fileName) ? FileSystem.GetFileLength(fileName) : 0,
            };

            return Trace(nameof(GetFileInformation), fileName, info, DokanResult.Success);
        }

        public NtStatus FindFiles(string fileName, out ICollection<FileInformation> files, IDokanFileInfo info)
        {
            // This function is not called because FindFilesWithPattern is implemented
            // Return DokanResult.NotImplemented in FindFilesWithPattern to make FindFiles called
            files = FindFilesHelper(fileName, "*");

            return Trace(nameof(FindFiles), fileName, info, DokanResult.Success);
        }

        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info)
        {
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(SetFileAttributes), fileName, info, DokanResult.AccessDenied);

            try
            {
                // MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
                // because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
                if (attributes != 0)
                {
                    fileName = TranslatePath(fileName);

                    FileSystem.SetAttributes(fileName, attributes);
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
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(SetFileTime), fileName, info, DokanResult.AccessDenied);

            fileName = TranslatePath(fileName);

            try
            {
                if (creationTime.HasValue)
                    FileSystem.SetCreationTime(fileName, creationTime.Value);

                if (lastAccessTime.HasValue)
                    FileSystem.SetLastAccessTime(fileName, lastAccessTime.Value);

                if (lastWriteTime.HasValue)
                    FileSystem.SetLastWriteTime(fileName, lastWriteTime.Value);

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
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(DeleteFile), fileName, info, DokanResult.AccessDenied);

            fileName = TranslatePath(fileName);

            if (!FileSystem.Exists(fileName))
                return Trace(nameof(DeleteFile), fileName, info, DokanResult.FileNotFound);

            if (FileSystem.DirectoryExists(fileName))
                return Trace(nameof(DeleteFile), fileName, info, DokanResult.AccessDenied);

            return Trace(nameof(DeleteFile), fileName, info, DokanResult.Success);
            // we just check here if we could delete the file - the true deletion is in Cleanup
        }

        public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info)
        {
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(DeleteDirectory), fileName, info, DokanResult.AccessDenied);

            fileName = TranslatePath(fileName);

            try
            {
                FileSystem.DeleteDirectory(fileName, recursive: false);

                return Trace(nameof(DeleteDirectory), fileName, info, DokanResult.Success);
            }
            catch
            {
                return Trace(nameof(DeleteDirectory), fileName, info, DokanResult.DirectoryNotEmpty);
            }

            // if dir is not empty it can't be deleted
        }

        public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
        {
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(MoveFile), oldName, info, DokanResult.AccessDenied);

            oldName = TranslatePath(oldName);
            newName = TranslatePath(newName);

            (info.Context as Stream)?.Dispose();
            info.Context = null;

            var exist = info.IsDirectory ? FileSystem.DirectoryExists(newName) : FileSystem.FileExists(newName);

            try
            {
                if (!exist)
                {
                    info.Context = null;

                    if (info.IsDirectory)
                        FileSystem.MoveDirectory(oldName, newName);
                    else
                        FileSystem.MoveFile(oldName, newName);

                    return Trace(nameof(MoveFile), oldName, info, DokanResult.Success, newName,
                        replace.ToString(CultureInfo.InvariantCulture));
                }
                else if (replace)
                {
                    info.Context = null;

                    if (info.IsDirectory) //Cannot replace directory destination - See MOVEFILE_REPLACE_EXISTING
                        return Trace(nameof(MoveFile), oldName, info, DokanResult.AccessDenied, newName,
                            replace.ToString(CultureInfo.InvariantCulture));

                    FileSystem.MoveFile(oldName, newName, overwrite: true);

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
            if (!FileSystem.CanWrite ||
                Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly) ||
                !(info.Context is Stream stream))
            {
                return Trace(nameof(SetEndOfFile), fileName, info, DokanResult.AccessDenied);
            }

            try
            {
                stream.SetLength(length);
                
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
            if (!FileSystem.CanWrite ||
                Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly) ||
                !(info.Context is Stream stream))
            {
                return Trace(nameof(SetEndOfFile), fileName, info, DokanResult.AccessDenied);
            }

            try
            {
                stream.SetLength(length);

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
            return DokanResult.NotImplemented;
        }

        public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info)
        {
            return DokanResult.NotImplemented;
        }

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
        {
            freeBytesAvailable = FileSystem.AvailableSpace;
            totalNumberOfBytes = FileSystem.Size;
            totalNumberOfFreeBytes = FileSystem.AvailableSpace;

            return Trace(nameof(GetDiskFreeSpace), null, info, DokanResult.Success, $"out {freeBytesAvailable}",
                $"out {totalNumberOfBytes}", $"out {totalNumberOfFreeBytes}");
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features,
            out string fileSystemName, out uint maximumComponentLength, ref uint volumeSerialNumber, IDokanFileInfo info)
        {
            volumeLabel = (FileSystem as DiscFileSystem)?.VolumeLabel;
            
            if (string.IsNullOrWhiteSpace(volumeLabel))
                volumeLabel = "NO NAME";

            fileSystemName = FileSystem.GetType().Name;

            if (fileSystemName.EndsWith("FileSystem", StringComparison.Ordinal))
            {
                fileSystemName = fileSystemName.Remove(fileSystemName.Length - "FileSystem".Length);
            }
            else if (fileSystemName.EndsWith("Reader", StringComparison.Ordinal))
            {
                fileSystemName = fileSystemName.Remove(fileSystemName.Length - "Reader".Length);
            }

            if (fileSystemName.Length <= 5)
            {
                fileSystemName = fileSystemName.ToUpperInvariant();
            }

            maximumComponentLength = 260;

            features = FileSystemFeatures.CasePreservedNames |
                       FileSystemFeatures.SupportsRemoteStorage |
                       FileSystemFeatures.UnicodeOnDisk;

            if (FileSystem is IWindowsFileSystem)
            {
                features |= FileSystemFeatures.NamedStreams;

                if (!Options.HasFlag(DokanDiscUtilsOptions.IgnoreSecurity))
                {
                    features |= FileSystemFeatures.PersistentAcls;
                }
            }

            if (FileSystem is IUnixFileSystem)
            {
                features |= FileSystemFeatures.CaseSensitiveSearch |
                    FileSystemFeatures.NamedStreams;
            }

            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
            {
                features |= FileSystemFeatures.ReadOnlyVolume;
            }

            if (FileSystem is DiscFileSystem dfs)
            {
                volumeSerialNumber = dfs.VolumeId;
            }

            return Trace(nameof(GetVolumeInformation), null, info, DokanResult.Success, $"out {volumeLabel}",
                $"out {features}", $"out {fileSystemName}");
        }

        public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections,
            IDokanFileInfo info)
        {
            try
            {
                if (!(FileSystem is IWindowsFileSystem wfs) || Options.HasFlag(DokanDiscUtilsOptions.IgnoreSecurity))
                {
                    security = null;
                    return Trace(nameof(GetFileSecurity), fileName, info, DokanResult.NotImplemented);
                }

                fileName = TranslatePath(fileName);

                var fs_security = wfs.GetSecurity(fileName);

                if (fs_security == null)
                {
                    security = null;
                    return Trace(nameof(GetFileSecurity), fileName, info, DokanResult.InvalidParameter);
                }

                var buffer = new byte[fs_security.BinaryLength];
                fs_security.GetBinaryForm(buffer, 0);

                security = new FileSecurity();
                security.SetSecurityDescriptorBinaryForm(buffer, sections);

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
            if (!FileSystem.CanWrite || Options.HasFlag(DokanDiscUtilsOptions.ForceReadOnly))
                return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.AccessDenied);

            try
            {
                if (!(FileSystem is IWindowsFileSystem wfs) || Options.HasFlag(DokanDiscUtilsOptions.IgnoreSecurity))
                {
                    return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.NotImplemented);
                }

                var fs_security = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);

                fileName = TranslatePath(fileName);

                wfs.SetSecurity(fileName, fs_security);

                return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.Success, sections.ToString());
            }
            catch (UnauthorizedAccessException)
            {
                return Trace(nameof(SetFileSecurity), fileName, info, DokanResult.AccessDenied, sections.ToString());
            }
        }

        public NtStatus Mounted(IDokanFileInfo info)
        {
            return Trace(nameof(Mounted), null, info, DokanResult.Success);
        }

        public NtStatus Unmounted(IDokanFileInfo info)
        {
            return Trace(nameof(Unmounted), null, info, DokanResult.Success);
        }

#if false
        public NtStatus FindStreams(string fileName, IntPtr enumContext, out string streamName, out long streamSize,
            IDokanFileInfo info)
        {
            streamName = string.Empty;
            streamSize = 0;
            return Trace(nameof(FindStreams), fileName, info, DokanResult.NotImplemented, enumContext.ToString(),
                $"out {streamName}", $"out {streamSize}");
        }
#endif

        public NtStatus FindStreams(string fileName, out ICollection<FileInformation> streams, IDokanFileInfo info)
        {
            if (FileSystem is IWindowsFileSystem wfs)
            {
                fileName = TranslatePath(fileName);

                streams = Array.ConvertAll(wfs.GetAlternateDataStreams(fileName),
                name =>
                {
                    var finfo = FileSystem.GetFileInfo(name);

                    return new FileInformation
                    {
                        Attributes = FilterAttributes(finfo.Attributes),
                        CreationTime = finfo.CreationTime,
                        LastAccessTime = finfo.LastAccessTime,
                        LastWriteTime = finfo.LastWriteTime,
                        Length = finfo.Length,
                        FileName = finfo.Name
                    };
                });

                return Trace(nameof(FindStreams), fileName, info, DokanResult.Success, $"Found {streams.Count} streams");
            }

            streams = new FileInformation[0];
            return Trace(nameof(FindStreams), fileName, info, DokanResult.NotImplemented);
        }

        private FileAttributes FilterAttributes(FileAttributes attributes)
        {
            if (Options.HasFlag(DokanDiscUtilsOptions.HiddenAsNormal))
            {
                attributes &= ~(FileAttributes.Hidden | FileAttributes.System);
            }

            return attributes;
        }

        public ICollection<FileInformation> FindFilesHelper(string fileName, string searchPattern)
        {
            fileName = TranslatePath(fileName);

            var files = FileSystem.GetFileSystemEntries(fileName, searchPattern)
                .Select(name => FileSystem.FileExists(name) ? FileSystem.GetFileInfo(name) : FileSystem.GetFileSystemInfo(name))
                .Where(finfo => finfo.Exists)
                .Select(finfo =>
                {
                    return new FileInformation
                    {
                        Attributes = FilterAttributes(finfo.Attributes),
                        CreationTime = finfo.CreationTime,
                        LastAccessTime = finfo.LastAccessTime,
                        LastWriteTime = finfo.LastWriteTime,
                        Length = (finfo as DiscFileInfo)?.Length ?? 0,
                        FileName = SanitizePath(finfo.Name)
                    };
                })
                .ToArray();

            return files;
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out ICollection<FileInformation> files,
            IDokanFileInfo info)
        {
            files = FindFilesHelper(fileName, searchPattern);

            return Trace(nameof(FindFilesWithPattern), fileName, info, DokanResult.Success);
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (!Options.HasFlag(DokanDiscUtilsOptions.LeaveFsOpen) &&
                        FileSystem is IDisposable disposable_filesystem)
                    {
                        disposable_filesystem.Dispose();
                    }

                    // TODO: dispose managed state (managed objects).
#if TRACE
                    logger.Dispose();
#endif
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.

                // TODO: set large fields to null.
                _transl.Clear();

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~DokanDiscUtils()
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

#endregion Implementation of IDokanOperations
    }
}
