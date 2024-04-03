using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

using DokanNet.Logging;
using DokanNet.Native;

using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0060 // Remove unused parameter

namespace DokanNet;

/// <summary>
/// The dokan operation proxy.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="DokanOperationProxy"/> class.
/// </remarks>
/// <param name="operations">
/// A <see cref="IDokanOperations"/> that contains the custom implementation of the driver.
/// </param>
/// <param name="logger">
/// A <see cref="ILogger"/> that handle all logging.
/// </param>
#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal sealed class DokanOperationProxy(IDokanOperations operations, ILogger logger)
{
#if NET6_0_OR_GREATER
    
    private static unsafe ReadOnlyDokanMemory<char> MemoryFromIntPtr(nint ptr)
        => new(ptr, MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)ptr).Length);

#else

    [DllImport("msvcrt", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
    private static extern int wcslen(nint ptr);

    private static ReadOnlyDokanMemory<char> MemoryFromIntPtr(nint ptr)
    {
        if (ptr == 0)
        {
            return default;
        }

        return new(ptr, wcslen(ptr));
    }

#endif

    private readonly IDokanOperations operations = operations;

    private readonly ILogger logger = logger;

    private uint serialNumber = (uint)operations.GetHashCode();

#region Enum masks
    /// <summary>
    /// To be used to mask out the <see cref="FileOptions"/> flags from what is returned 
    /// from <see cref="Native.NativeMethods.DokanMapKernelToUserCreateFileFlags"/>.
    /// </summary>
    private const int FileOptionsMask =
        (int)
        (FileOptions.Asynchronous | FileOptions.DeleteOnClose | FileOptions.Encrypted
        | FileOptions.None | FileOptions.RandomAccess | FileOptions.SequentialScan
        | FileOptions.WriteThrough);

    /// <summary>
    /// To be used to mask out the <see cref="FileAttributes"/> flags from what is returned 
    /// from <see cref="Native.NativeMethods.DokanMapKernelToUserCreateFileFlags"/>.
    /// Note that some flags where introduces in .NET Framework 4.5, and is not supported 
    /// in .NET Framework 4. 
    /// </summary>
    private const int FileAttributeMask = (int)(
        FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System
        | FileAttributes.Directory | FileAttributes.Archive | FileAttributes.Device
        | FileAttributes.Normal | FileAttributes.Temporary | FileAttributes.SparseFile
        | FileAttributes.ReparsePoint | FileAttributes.Compressed | FileAttributes.Offline
        | FileAttributes.NotContentIndexed | FileAttributes.Encrypted
#if NET45_OR_GREATER || NETSTANDARD || NETCOREAPP
        | FileAttributes.IntegrityStream | FileAttributes.NoScrubData
#endif
    );

    /// <summary>
    /// To be used to mask out the <see cref="NativeFileAccess"/> flags.
    /// </summary>
    private const uint FileAccessMask =
        (uint)
        (NativeFileAccess.ReadData | NativeFileAccess.WriteData | NativeFileAccess.AppendData
        | NativeFileAccess.ReadExtendedAttributes | NativeFileAccess.WriteExtendedAttributes | NativeFileAccess.Execute
        | NativeFileAccess.DeleteChild | NativeFileAccess.ReadAttributes | NativeFileAccess.WriteAttributes
        | NativeFileAccess.Delete | NativeFileAccess.ReadPermissions | NativeFileAccess.ChangePermissions
        | NativeFileAccess.SetOwnership | NativeFileAccess.Synchronize | NativeFileAccess.AccessSystemSecurity
        | NativeFileAccess.MaximumAllowed | NativeFileAccess.GenericAll | NativeFileAccess.GenericExecute
        | NativeFileAccess.GenericWrite | NativeFileAccess.GenericRead);

    /// <summary>
    /// To be used to mask out the <see cref="FileShare"/> flags.
    /// </summary>
    private const int FileShareMask =
        (int)
        (FileShare.ReadWrite | FileShare.Delete | FileShare.Inheritable);

    #endregion

    /// <summary>
    /// CreateFile is called each time a request is made on a file system object.
    /// 
    /// In case <see cref="FileMode.OpenOrCreate"/> and
    /// <see cref="FileMode.Create"/> are opening successfully a already
    /// existing file, you have to return <see cref="DokanResult.AlreadyExists"/> instead of <see cref="NtStatus.Success"/>.
    /// 
    /// If the file is a directory, CreateFile is also called.
    /// In this case, CreateFile should return <see cref="NtStatus.Success"/> when that directory
    /// can be opened and <see cref="DokanFileInfo.IsDirectory"/> has to be set to <c>true</c>.
    /// 
    /// <see cref="DokanFileInfo.Context"/> can be used to store data (like <see cref="FileStream"/>)
    /// that can be retrieved in all other request related to the context.
    /// </summary>
    /// <param name="rawFileName">File path requested by the Kernel on the FileSystem.</param>
    /// <param name="securityContext">SecurityContext, see <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff550613(v=vs.85).aspx">IO_SECURITY_CONTEXT structure (MSDN)</a>.</param>
    /// <param name="rawDesiredAccess">Specifies an <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff540466(v=vs.85).aspx">ACCESS_MASK (MSDN)</a> value that determines the requested access to the object.</param>
    /// <param name="rawFileAttributes">Specifies one or more FILE_ATTRIBUTE_XXX flags, which represent the file attributes to set if you create or overwrite a file.</param>
    /// <param name="rawShareAccess">Type of share access, which is specified as zero or any combination of <see cref="FileShare"/>.</param>
    /// <param name="rawCreateDisposition">Specifies the action to perform if the file does or does not exist.</param>
    /// <param name="rawCreateOptions">Specifies the options to apply when the driver creates or opens the file.</param>
    /// <param name="rawFileInfo">>An <see cref="DokanFileInfo"/> with information about the file or directory.</param>
    /// <returns>The <see cref="NtStatus"/>.</returns>
    /// \see <a href="https://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx">ZwCreateFile routine (MSDN)</a>
    /// <see cref="DokanNet.IDokanOperations.CreateFile"/>
    public NtStatus ZwCreateFileProxy(
        nint rawFileName,
        nint securityContext,
        uint rawDesiredAccess,
        uint rawFileAttributes,
        uint rawShareAccess,
        uint rawCreateDisposition,
        uint rawCreateOptions,
        ref DokanFileInfo rawFileInfo)
    {
        try
        {
            NativeMethods.DokanMapKernelToUserCreateFileFlags(
                rawDesiredAccess,
                rawFileAttributes,
                rawCreateOptions,
                rawCreateDisposition,
                out var outDesiredAccess,
                out var fileAttributesAndFlags,
                out var creationDisposition);

            var fileAttributes = (FileAttributes)(fileAttributesAndFlags & FileAttributeMask);
            var fileOptions = (FileOptions)(fileAttributesAndFlags & FileOptionsMask);
            var desiredAccess = (NativeFileAccess)(outDesiredAccess & FileAccessMask);
            var shareAccess = (FileShare)(rawShareAccess & FileShareMask);

            if (logger.DebugEnabled)
            {
                logger.Debug($"CreateFileProxy : {rawFileName}");
                logger.Debug($"\tCreationDisposition\t{(FileMode)creationDisposition}");
                logger.Debug($"\tFileAccess\t{(FileAccess)rawDesiredAccess}");
                logger.Debug($"\tFileShare\t{(FileShare)rawShareAccess}");
                logger.Debug($"\tFileOptions\t{fileOptions}");
                logger.Debug($"\tFileAttributes\t{fileAttributes}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.CreateFile(
                MemoryFromIntPtr(rawFileName),
                desiredAccess,
                shareAccess,
                (FileMode)creationDisposition,
                fileOptions,
                fileAttributes,
                ref rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"CreateFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"CreateFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public void CleanupProxy(nint rawFileName, ref DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"CleanupProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            operations.Cleanup(MemoryFromIntPtr(rawFileName), ref rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"CleanupProxy : {rawFileName}");
            }
        }
        catch (Exception ex)
        {
            logger.Error($"CleanupProxy : {rawFileName} Throw : {ex.Message}");
        }
    }

    ////

    public void CloseFileProxy(nint rawFileName, ref DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"CloseFileProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            operations.CloseFile(MemoryFromIntPtr(rawFileName), ref rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"CloseFileProxy : {rawFileName}");
            }
        }
        catch (Exception ex)
        {
            logger.Error($"CloseFileProxy : {rawFileName} Throw : {ex.Message}");
        }
        finally
        {
            rawFileInfo.Context = null;
        }
    }

    ////

    public NtStatus ReadFileProxy(
        nint rawFileName,
        nint rawBuffer,
        uint rawBufferLength,
        ref int rawReadLength,
        long rawOffset,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"ReadFileProxy : {rawFileName}");
                logger.Debug($"\tBufferLength\t{rawBufferLength}");
                logger.Debug($"\tOffset\t{rawOffset}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.ReadFile(MemoryFromIntPtr(rawFileName), new(rawBuffer, (int)rawBufferLength), out rawReadLength, rawOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"ReadFileProxy : {rawFileName} Return : {result} ReadLength : {rawReadLength}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"ReadFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus WriteFileProxy(
        nint rawFileName,
        nint rawBuffer,
        uint rawNumberOfBytesToWrite,
        ref int rawNumberOfBytesWritten,
        long rawOffset,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"WriteFileProxy : {rawFileName}");
                logger.Debug($"\tNumberOfBytesToWrite\t{rawNumberOfBytesToWrite}");
                logger.Debug($"\tOffset\t{rawOffset}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.WriteFile(MemoryFromIntPtr(rawFileName), new(rawBuffer, (int)rawNumberOfBytesToWrite), out rawNumberOfBytesWritten, rawOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"WriteFileProxy : {rawFileName} Return : {result} NumberOfBytesWritten : {rawNumberOfBytesWritten}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"WriteFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus FlushFileBuffersProxy(nint rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FlushFileBuffersProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FlushFileBuffers(MemoryFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"FlushFileBuffersProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FlushFileBuffersProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus GetFileInformationProxy(
        nint rawFileName,
        ref BY_HANDLE_FILE_INFORMATION rawHandleFileInformation,
        in DokanFileInfo rawFileInfo)
    {
        var fileNamePtr = MemoryFromIntPtr(rawFileName);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"GetFileInformationProxy : {fileNamePtr}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.GetFileInformation(fileNamePtr, out var fi, rawFileInfo);

            if (result == DokanResult.Success)
            {
                //Debug.Assert(fi.FileName is not null, "FileName must not be null");
                if (logger.DebugEnabled)
                {
                    logger.Debug($"\tFileName\t{fileNamePtr}");
                    logger.Debug($"\tAttributes\t{fi.Attributes}");
                    logger.Debug($"\tCreationTime\t{fi.CreationTime}");
                    logger.Debug($"\tLastAccessTime\t{fi.LastAccessTime}");
                    logger.Debug($"\tLastWriteTime\t{fi.LastWriteTime}");
                    logger.Debug($"\tLength\t{fi.Length}");
                }

                rawHandleFileInformation.dwFileAttributes = (uint)fi.Attributes /* + FILE_ATTRIBUTE_VIRTUAL*/;

                var ctime = ToFileTime(fi.CreationTime);
                rawHandleFileInformation.ftCreationTime.dwHighDateTime = (int)(ctime >> 32);
                rawHandleFileInformation.ftCreationTime.dwLowDateTime = (int)(ctime & 0xffffffff);

                var atime = ToFileTime(fi.LastAccessTime);
                rawHandleFileInformation.ftLastAccessTime.dwHighDateTime = (int)(atime >> 32);
                rawHandleFileInformation.ftLastAccessTime.dwLowDateTime = (int)(atime & 0xffffffff);

                var mtime = ToFileTime(fi.LastWriteTime);
                rawHandleFileInformation.ftLastWriteTime.dwHighDateTime = (int)(mtime >> 32);
                rawHandleFileInformation.ftLastWriteTime.dwLowDateTime = (int)(mtime & 0xffffffff);

                rawHandleFileInformation.dwVolumeSerialNumber = serialNumber;

                rawHandleFileInformation.nFileSizeLow = (uint)(fi.Length & 0xffffffff);
                rawHandleFileInformation.nFileSizeHigh = (uint)(fi.Length >> 32);

                rawHandleFileInformation.dwNumberOfLinks = fi.NumberOfLinks;

                var index = fi.FileIndex;
                
                if (index == 0)
                {
#if NETCOREAPP
                    index = string.GetHashCode(fileNamePtr.Span, StringComparison.Ordinal);
#elif NETSTANDARD2_1_OR_GREATER
                    index = rawFileName.ToString().GetHashCode(StringComparison.Ordinal);
#else
                    index = rawFileName.ToString().GetHashCode();
#endif
                }

                rawHandleFileInformation.nFileIndexHigh = (uint)(index >> 32);
                rawHandleFileInformation.nFileIndexLow = (uint)(index & 0xffffffff);
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"GetFileInformationProxy : {fileNamePtr} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"GetFileInformationProxy : {fileNamePtr} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus FindFilesProxy(nint rawFileName, nint rawFillFindData, in DokanFileInfo rawFileInfo)
    {
        var startTime = Environment.TickCount;

        var fileNamePtr = MemoryFromIntPtr(rawFileName);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesProxy : {fileNamePtr}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FindFiles(fileNamePtr, out var files, rawFileInfo);

            if (result == DokanResult.Success)
            {
                Debug.Assert(files is not null, "Files must not be null");

                var count = 0L;

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files!)
                {
                    count++;

                    if (unchecked(Environment.TickCount - startTime) >= 30000)
                    {
                        logger.Error($"FindFilesProxy : Timed out at {fileNamePtr} after {count} files");
                        return NtStatus.IoTimeout;
                    }

                    if (logger.DebugEnabled)
                    {
                        logger.Debug($"\tFileName\t{fi.FileName}");
                        logger.Debug($"\t\tAttributes\t{fi.Attributes}");
                        logger.Debug($"\t\tCreationTime\t{fi.CreationTime}");
                        logger.Debug($"\t\tLastAccessTime\t{fi.LastAccessTime}");
                        logger.Debug($"\t\tLastWriteTime\t{fi.LastWriteTime}");
                        logger.Debug($"\t\tLength\t{fi.Length}");
                    }

                    AddFileFindDataTo(rawFillFindData, rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesProxy : {fileNamePtr} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindFilesProxy : {fileNamePtr} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus FindFilesWithPatternProxy(
        nint rawFileName,
        nint rawSearchPattern,
        nint rawFillFindData,
        in DokanFileInfo rawFileInfo)
    {
        var startTime = Environment.TickCount;

        var fileNamePtr = MemoryFromIntPtr(rawFileName);
        var searchPatternPtr = MemoryFromIntPtr(rawSearchPattern);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesWithPatternProxy : {fileNamePtr}");
                logger.Debug($"\trawSearchPattern\t{searchPatternPtr}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            // TODO(someone): Allow userland FS to set FindFiles preference at mount time and nullify the callback not used.
            var result = operations.FindFilesWithPattern(fileNamePtr, searchPatternPtr, out var files, rawFileInfo);

            Debug.Assert(files is not null, "Files must not be null");
            
            if (result == DokanResult.Success)
            {
                var count = 0L;

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files!)
                {
                    count++;

                    if (unchecked(Environment.TickCount - startTime) >= 30000)
                    {
                        logger.Error($"FindFilesWithPatternProxy : Timed out at {fileNamePtr} with pattern {searchPatternPtr} after {count} files");
                        return NtStatus.IoTimeout;
                    }

                    if (logger.DebugEnabled)
                    {
                        logger.Debug($"\tFileName\t{fi.FileName}");
                        logger.Debug($"\t\tAttributes\t{fi.Attributes}");
                        logger.Debug($"\t\tCreationTime\t{fi.CreationTime}");
                        logger.Debug($"\t\tLastAccessTime\t{fi.LastAccessTime}");
                        logger.Debug($"\t\tLastWriteTime\t{fi.LastWriteTime}");
                        logger.Debug($"\t\tLength\t{fi.Length}");
                    }

                    AddFileFindDataTo(rawFillFindData, rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesWithPatternProxy : {fileNamePtr} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindFilesWithPatternProxy : {fileNamePtr} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    /// <summary>
    /// Call the function pointer <paramref name="rawFillFindData"/> using data in <paramref name="rawFileInfo"/> and <paramref name="fi"/>.
    /// </summary>
    /// <param name="rawFillFindData">Pointer to unmanaged function of type <see cref="FILL_FIND_FILE_DATA"/> to be called.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/> to be used when calling <paramref name="rawFillFindData"/>.</param>
    /// <param name="fi">A <see cref="ByHandleFileInformation"/> with information to be used when calling <paramref name="rawFillFindData"/>.</param>
    private static unsafe void AddFileFindDataTo(nint rawFillFindData, in DokanFileInfo rawFileInfo, in FindFileInformation fi)
    {
        var fill = (delegate* unmanaged[Stdcall]<in WIN32_FIND_DATA, in DokanFileInfo, long>)rawFillFindData;

        Debug.Assert(!fi.FileName.IsEmpty, "FileName must not be empty or null");
        var ctime = ToFileTime(fi.CreationTime);
        var atime = ToFileTime(fi.LastAccessTime);
        var mtime = ToFileTime(fi.LastWriteTime);
        var data = new WIN32_FIND_DATA
        {
            dwFileAttributes = fi.Attributes,
            ftCreationTime =
                {
                    dwHighDateTime = (int) (ctime >> 32),
                    dwLowDateTime = (int) (ctime & 0xffffffff)
                },
            ftLastAccessTime =
                {
                    dwHighDateTime = (int) (atime >> 32),
                    dwLowDateTime = (int) (atime & 0xffffffff)
                },
            ftLastWriteTime =
                {
                    dwHighDateTime = (int) (mtime >> 32),
                    dwLowDateTime = (int) (mtime & 0xffffffff)
                },
            nFileSizeLow = (uint)(fi.Length & 0xffffffff),
            nFileSizeHigh = (uint)(fi.Length >> 32),
            FileName = fi.FileName.Span,
            AlternateFileName = fi.ShortFileName.Span
        };

        fill(data, rawFileInfo);
    }

    public NtStatus FindStreamsProxy(nint rawFileName, nint rawFillFindData, nint findStreamContext, in DokanFileInfo rawFileInfo)
    {
        var startTime = Environment.TickCount;

        var fileNamePtr = MemoryFromIntPtr(rawFileName);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindStreamsProxy: {fileNamePtr}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FindStreams(fileNamePtr, out var files, rawFileInfo);

            Debug.Assert(!(result == DokanResult.NotImplemented && files is null));
            if (result == DokanResult.Success)
            {
                var count = 0L;

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files!)
                {
                    count++;

                    if (unchecked(Environment.TickCount - startTime) >= 30000)
                    {
                        logger.Error($"FindStreamsProxy : Timed out at {fileNamePtr} after {count} names");
                        return NtStatus.IoTimeout;
                    }

                    if (logger.DebugEnabled)
                    {
                        logger.Debug($"\tFileName\t{fi.FileName}");
                        logger.Debug($"\t\tLength\t{fi.Length}");
                    }

                    AddFindStreamDataTo(rawFillFindData, rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindStreamsProxy : {fileNamePtr} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindStreamsProxy : {fileNamePtr} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    /// <summary>
    /// Call the function pointer <paramref name="rawFillStreamData"/> using data in <paramref name="rawFileInfo"/> and <paramref name="fi"/>.
    /// </summary>
    /// <param name="rawFillStreamData">Pointer to unmanaged function of type <see cref="FILL_FIND_STREAM_DATA"/> to be called.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/> to be used when calling <paramref name="rawFillStreamData"/>.</param>
    /// <param name="fi">A <see cref="ByHandleFileInformation"/> with information to be used when calling <paramref name="rawFillStreamData"/>.</param>
    private static unsafe void AddFindStreamDataTo(nint rawFillStreamData, in DokanFileInfo rawFileInfo, FindFileInformation fi)
    {
        var fill = (delegate* unmanaged[Stdcall]<in WIN32_FIND_STREAM_DATA, in DokanFileInfo, long>)rawFillStreamData;

        Debug.Assert(!fi.FileName.IsEmpty, "FileName must not be empty or null");

        var data = new WIN32_FIND_STREAM_DATA
        {
            StreamSize = fi.Length,
            StreamName = fi.FileName.Span
        };
        //ZeroMemory(&data, sizeof(WIN32_FIND_DATAW));

        fill(data, rawFileInfo);
    }

    ////

    public NtStatus SetEndOfFileProxy(nint rawFileName, long rawByteOffset, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetEndOfFileProxy : {rawFileName}");
                logger.Debug($"\tByteOffset\t{rawByteOffset}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetEndOfFile(MemoryFromIntPtr(rawFileName), rawByteOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetEndOfFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetEndOfFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus SetAllocationSizeProxy(nint rawFileName, long rawLength, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetAllocationSizeProxy : {rawFileName}");
                logger.Debug($"\tLength\t{rawLength}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetAllocationSize(MemoryFromIntPtr(rawFileName), rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetAllocationSizeProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetAllocationSizeProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus SetFileAttributesProxy(nint rawFileName, uint rawAttributes, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileAttributesProxy : {rawFileName}");
                logger.Debug($"\tAttributes\t{(FileAttributes)rawAttributes}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetFileAttributes(MemoryFromIntPtr(rawFileName), (FileAttributes)rawAttributes, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileAttributesProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileAttributesProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus SetFileTimeProxy(
        nint rawFileName,
        ref FILETIME rawCreationTime,
        ref FILETIME rawLastAccessTime,
        ref FILETIME rawLastWriteTime,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            var ctime = (rawCreationTime.dwLowDateTime != 0 || rawCreationTime.dwHighDateTime != 0) &&
                        (rawCreationTime.dwLowDateTime != -1 || rawCreationTime.dwHighDateTime != -1)
                ? DateTime.FromFileTime(((long)rawCreationTime.dwHighDateTime << 32) |
                                        (uint)rawCreationTime.dwLowDateTime)
                : (DateTime?)null;
            var atime = (rawLastAccessTime.dwLowDateTime != 0 || rawLastAccessTime.dwHighDateTime != 0) &&
                        (rawLastAccessTime.dwLowDateTime != -1 || rawLastAccessTime.dwHighDateTime != -1)
                ? DateTime.FromFileTime(((long)rawLastAccessTime.dwHighDateTime << 32) |
                                        (uint)rawLastAccessTime.dwLowDateTime)
                : (DateTime?)null;
            var mtime = (rawLastWriteTime.dwLowDateTime != 0 || rawLastWriteTime.dwHighDateTime != 0) &&
                        (rawLastWriteTime.dwLowDateTime != -1 || rawLastWriteTime.dwHighDateTime != -1)
                ? DateTime.FromFileTime(((long)rawLastWriteTime.dwHighDateTime << 32) |
                                        (uint)rawLastWriteTime.dwLowDateTime)
                : (DateTime?)null;

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileTimeProxy : {rawFileName}");
                logger.Debug($"\tCreateTime\t{ctime}");
                logger.Debug($"\tAccessTime\t{atime}");
                logger.Debug($"\tWriteTime\t{mtime}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetFileTime(MemoryFromIntPtr(rawFileName), ctime, atime, mtime, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileTimeProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileTimeProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus DeleteFileProxy(nint rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteFileProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.DeleteFile(MemoryFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"DeleteFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus DeleteDirectoryProxy(nint rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteDirectoryProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.DeleteDirectory(MemoryFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteDirectoryProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"DeleteDirectoryProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus MoveFileProxy(
        nint rawFileName,
        nint rawNewFileName,
        bool rawReplaceIfExisting,
        ref DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"MoveFileProxy : {rawFileName}");
                logger.Debug($"\tNewFileName\t{rawNewFileName}");
                logger.Debug($"\tReplaceIfExisting\t{rawReplaceIfExisting}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.MoveFile(MemoryFromIntPtr(rawFileName), MemoryFromIntPtr(rawNewFileName), rawReplaceIfExisting, ref rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"MoveFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"MoveFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus LockFileProxy(nint rawFileName, long rawByteOffset, long rawLength, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"LockFileProxy : {rawFileName}");
                logger.Debug($"\tByteOffset\t{rawByteOffset}");
                logger.Debug($"\tLength\t{rawLength}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.LockFile(MemoryFromIntPtr(rawFileName), rawByteOffset, rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"LockFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"LockFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus UnlockFileProxy(
        nint rawFileName,
        long rawByteOffset,
        long rawLength,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"UnlockFileProxy : {rawFileName}");
                logger.Debug($"\tByteOffset\t{rawByteOffset}");
                logger.Debug($"\tLength\t{rawLength}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.UnlockFile(MemoryFromIntPtr(rawFileName), rawByteOffset, rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"UnlockFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"UnlockFileProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    ////

    public NtStatus GetDiskFreeSpaceProxy(
        ref long rawFreeBytesAvailable,
        ref long rawTotalNumberOfBytes,
        ref long rawTotalNumberOfFreeBytes,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"GetDiskFreeSpaceProxy:");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.GetDiskFreeSpace(
                out rawFreeBytesAvailable,
                out rawTotalNumberOfBytes,
                out rawTotalNumberOfFreeBytes,
                rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"\tFreeBytesAvailable\t{rawFreeBytesAvailable}");
                logger.Debug($"\tTotalNumberOfBytes\t{rawTotalNumberOfBytes}");
                logger.Debug($"\tTotalNumberOfFreeBytes\t{rawTotalNumberOfFreeBytes}");
                logger.Debug($"GetDiskFreeSpaceProxy Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"GetDiskFreeSpaceProxy Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus GetVolumeInformationProxy(
        StringBuilder rawVolumeNameBuffer,
        uint rawVolumeNameSize,
        ref uint rawVolumeSerialNumber,
        ref uint rawMaximumComponentLength,
        ref FileSystemFeatures rawFileSystemFlags,
        StringBuilder rawFileSystemNameBuffer,
        uint rawFileSystemNameSize,
        in DokanFileInfo rawFileInfo)
    {
        rawVolumeSerialNumber = serialNumber;
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"GetVolumeInformationProxy:");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.GetVolumeInformation(out var volumeName, out rawFileSystemFlags, out var name, out var maximumComponentLength, ref rawVolumeSerialNumber, rawFileInfo);

            if (result == DokanResult.Success)
            {
                Debug.Assert(!string.IsNullOrEmpty(name), "name must not be null");
                Debug.Assert(!string.IsNullOrEmpty(volumeName), "Label must not be null");
                rawVolumeNameBuffer.Append(volumeName);
                rawFileSystemNameBuffer.Append(name);
                rawMaximumComponentLength = maximumComponentLength;
                serialNumber = rawVolumeSerialNumber;

                if (logger.DebugEnabled)
                {
                    logger.Debug($"\tVolumeNameBuffer\t{rawVolumeNameBuffer}");
                    logger.Debug($"\tFileSystemNameBuffer\t{rawFileSystemNameBuffer}");
                    logger.Debug($"\tVolumeSerialNumber\t{rawVolumeSerialNumber}");
                    logger.Debug($"\tFileSystemFlags\t{rawFileSystemFlags}");
                    logger.Debug($"\tMaximumComponentLength\t{rawMaximumComponentLength}");
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"GetVolumeInformationProxy Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"GetVolumeInformationProxy Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus MountedProxy(nint mountPoint, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"MountedProxy:");
                logger.Debug($"\tMountPoint\t{mountPoint}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.Mounted(MemoryFromIntPtr(mountPoint), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"MountedProxy Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"MountedProxy Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus UnmountedProxy(in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"UnmountedProxy:");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.Unmounted(rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"UnmountedProxy Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"UnmountedProxy Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus GetFileSecurityProxy(
        nint rawFileName,
        ref SECURITY_INFORMATION rawRequestedInformation,
        nint rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        ref uint rawSecurityDescriptorLengthNeeded,
        in DokanFileInfo rawFileInfo)
    {
        var sect = AccessControlSections.None;
        if (rawRequestedInformation.HasFlag(SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Owner;
        }

        if (rawRequestedInformation.HasFlag(SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Group;
        }

        if (rawRequestedInformation.HasFlag(SECURITY_INFORMATION.DACL_SECURITY_INFORMATION) ||
            rawRequestedInformation.HasFlag(SECURITY_INFORMATION.PROTECTED_DACL_SECURITY_INFORMATION) ||
            rawRequestedInformation.HasFlag(SECURITY_INFORMATION.UNPROTECTED_DACL_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Access;
        }

        if (rawRequestedInformation.HasFlag(SECURITY_INFORMATION.SACL_SECURITY_INFORMATION) ||
            rawRequestedInformation.HasFlag(SECURITY_INFORMATION.PROTECTED_SACL_SECURITY_INFORMATION) ||
            rawRequestedInformation.HasFlag(SECURITY_INFORMATION.UNPROTECTED_SACL_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Audit;
        }

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"GetFileSecurityProxy : {rawFileName}");
                logger.Debug($"\tFileSystemSecurity\t{sect}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.GetFileSecurity(MemoryFromIntPtr(rawFileName), out var sec, sect, rawFileInfo);
            if (result == DokanResult.Success /*&& sec is not null*/)
            {
                Debug.Assert(sec is not null, $"{nameof(sec)} must not be null");
                if (logger.DebugEnabled)
                {
                    logger.Debug($"\tFileSystemSecurity Result : {sec}");
                }

                var buffer = sec!.GetSecurityDescriptorBinaryForm();
                rawSecurityDescriptorLengthNeeded = (uint)buffer.Length;
                if (buffer.Length > rawSecurityDescriptorLength)
                {
                    return DokanResult.BufferOverflow;
                }

                Marshal.Copy(buffer, 0, rawSecurityDescriptor, buffer.Length);
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"GetFileSecurityProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"GetFileSecurityProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    public NtStatus SetFileSecurityProxy(
        nint rawFileName,
        ref SECURITY_INFORMATION rawSecurityInformation,
        nint rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        in DokanFileInfo rawFileInfo)
    {
        var sect = AccessControlSections.None;
        if (rawSecurityInformation.HasFlag(SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Owner;
        }

        if (rawSecurityInformation.HasFlag(SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Group;
        }

        if (rawSecurityInformation.HasFlag(SECURITY_INFORMATION.DACL_SECURITY_INFORMATION) ||
            rawSecurityInformation.HasFlag(SECURITY_INFORMATION.PROTECTED_DACL_SECURITY_INFORMATION) ||
            rawSecurityInformation.HasFlag(SECURITY_INFORMATION.UNPROTECTED_DACL_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Access;
        }

        if (rawSecurityInformation.HasFlag(SECURITY_INFORMATION.SACL_SECURITY_INFORMATION) ||
            rawSecurityInformation.HasFlag(SECURITY_INFORMATION.PROTECTED_SACL_SECURITY_INFORMATION) ||
            rawSecurityInformation.HasFlag(SECURITY_INFORMATION.UNPROTECTED_SACL_SECURITY_INFORMATION))
        {
            sect |= AccessControlSections.Audit;
        }

        var buffer = new byte[rawSecurityDescriptorLength];
        try
        {
            Marshal.Copy(rawSecurityDescriptor, buffer, 0, (int)rawSecurityDescriptorLength);
            var sec = rawFileInfo.IsDirectory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            sec.SetSecurityDescriptorBinaryForm(buffer);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileSecurityProxy : {rawFileName}");
                logger.Debug($"\tAccessControlSections\t{sect}");
                logger.Debug($"\tFileSystemSecurity\t{sec}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetFileSecurity(MemoryFromIntPtr(rawFileName), sec, sect, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileSecurityProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileSecurityProxy : {rawFileName} Throw : {ex.Message}");
            return ex.ToNtStatus();
        }
    }

    /// <summary>
    /// Converts the value of <paramref name="dateTime"/> to a Windows file time.
    /// If <paramref name="dateTime"/> is <c>null</c> or before 12:00 midnight January 1, 1601 C.E. UTC, it returns <c>0</c>.
    /// </summary>
    /// <param name="dateTime">
    /// The date Time.
    /// </param>
    /// <returns>
    /// The value of <paramref name="dateTime"/> expressed as a Windows file time
    /// -or- it returns <c>0</c> if <paramref name="dateTime"/> is before 12:00 midnight January 1, 1601 C.E. UTC or <c>null</c>.
    /// </returns>
    /// \see <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa365739(v=vs.85).aspx">WIN32_FILE_ATTRIBUTE_DATA structure (MSDN)</a>
    [Pure]
    private static long ToFileTime(DateTime? dateTime) => dateTime.HasValue && (dateTime.Value >= DateTime.FromFileTime(0))
            ? dateTime.Value.ToFileTime()
            : 0;

    #region Nested type: FILL_FIND_FILE_DATA

    /// <summary>
    /// Used to add an entry in <see cref="DokanOperationProxy.FindFilesProxy"/> and <see cref="DokanOperationProxy.FindFilesWithPatternProxy"/>.
    /// </summary>
    /// <param name="rawFindData">A <see cref="WIN32_FIND_DATA"/>.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/>.</param>
    /// <returns><c>1</c> if buffer is full, otherwise <c>0</c> (currently it never returns <c>1</c>)</returns>
    /// <remarks>This is the same delegate as <c>PFillFindData</c> (dokan.h) in the C++ version of Dokan.</remarks>
    private delegate long FILL_FIND_FILE_DATA(
        ref WIN32_FIND_DATA rawFindData, in DokanFileInfo rawFileInfo);

#endregion Nested type: FILL_FIND_FILE_DATA

#region Nested type: FILL_FIND_STREAM_DATA

    /// <summary>
    /// Used to add an entry in <see cref="DokanOperationProxy.FindStreamsProxy"/>.
    /// </summary>
    /// <param name="rawFindData">A <see cref="WIN32_FIND_STREAM_DATA"/>.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/>.</param>
    /// <returns><c>1</c> if buffer is full, otherwise <c>0</c> (currently it never returns <c>1</c>)</returns>
    /// <remarks>This is the same delegate as <c>PFillFindStreamData</c> (dokan.h) in the C++ version of Dokan.</remarks>
    private delegate long FILL_FIND_STREAM_DATA(
        ref WIN32_FIND_STREAM_DATA rawFindData, in DokanFileInfo rawFileInfo);

#endregion Nested type: FILL_FIND_STREAM_DATA
}
