using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
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
internal sealed class DokanOperationProxy
{
#if NET6_0_OR_GREATER
    
    unsafe private static ReadOnlySpan<char> SpanFromIntPtr(IntPtr ptr)
        => MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)ptr.ToPointer());

#else

    [DllImport("msvcrt", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
    private static extern int wcslen(IntPtr ptr);

    unsafe private static ReadOnlySpan<char> SpanFromIntPtr(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return default;
        }

        return new(ptr.ToPointer(), wcslen(ptr));
    }

#endif

    #region Delegates

    public delegate NtStatus ZwCreateFileDelegate(
        IntPtr rawFileName,
        IntPtr securityContext,
        uint rawDesiredAccess,
        uint rawFileAttributes,
        uint rawShareAccess,
        uint rawCreateDisposition,
        uint rawCreateOptions,
        ref DokanFileInfo dokanFileInfo);

    public delegate void CleanupDelegate(
        IntPtr rawFileName,
        ref DokanFileInfo rawFileInfo);

    public delegate void CloseFileDelegate(
        IntPtr rawFileName,
        ref DokanFileInfo rawFileInfo);

    public delegate NtStatus ReadFileDelegate(
        IntPtr rawFileName,
        IntPtr rawBuffer,
        uint rawBufferLength,
        ref int rawReadLength,
        long rawOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus WriteFileDelegate(
        IntPtr rawFileName,
        IntPtr rawBuffer,
        uint rawNumberOfBytesToWrite,
        ref int rawNumberOfBytesWritten,
        long rawOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus FlushFileBuffersDelegate(
        IntPtr rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus GetFileInformationDelegate(
        IntPtr rawFileName,
        ref BY_HANDLE_FILE_INFORMATION handleFileInfo,
        in DokanFileInfo fileInfo);

    public delegate NtStatus FindFilesDelegate(
        IntPtr rawFileName,
        IntPtr rawFillFindData,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus FindFilesWithPatternDelegate(
        IntPtr rawFileName,
        IntPtr rawSearchPattern,
        IntPtr rawFillFindData,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileAttributesDelegate(
        IntPtr rawFileName,
        uint rawAttributes,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileTimeDelegate(
        IntPtr rawFileName,
        ref FILETIME rawCreationTime,
        ref FILETIME rawLastAccessTime,
        ref FILETIME rawLastWriteTime,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus DeleteFileDelegate(
        IntPtr rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus DeleteDirectoryDelegate(
        IntPtr rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus MoveFileDelegate(
        IntPtr rawFileName,
        IntPtr rawNewFileName,
        [MarshalAs(UnmanagedType.Bool)] bool rawReplaceIfExisting,
        ref DokanFileInfo rawFileInfo);

    public delegate NtStatus SetEndOfFileDelegate(
        IntPtr rawFileName,
        long rawByteOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetAllocationSizeDelegate(
        IntPtr rawFileName,
        long rawLength,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus LockFileDelegate(
        IntPtr rawFileName,
        long rawByteOffset, long rawLength,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus UnlockFileDelegate(
        IntPtr rawFileName,
        long rawByteOffset, long rawLength,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus GetDiskFreeSpaceDelegate(
        ref long rawFreeBytesAvailable, ref long rawTotalNumberOfBytes, ref long rawTotalNumberOfFreeBytes,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus GetVolumeInformationDelegate(
        [MarshalAs(UnmanagedType.LPWStr)] StringBuilder rawVolumeNameBuffer,
        uint rawVolumeNameSize,
        ref uint rawVolumeSerialNumber,
        ref uint rawMaximumComponentLength,
        ref FileSystemFeatures rawFileSystemFlags,
        [MarshalAs(UnmanagedType.LPWStr)] StringBuilder rawFileSystemNameBuffer,
        uint rawFileSystemNameSize,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus GetFileSecurityDelegate(
        IntPtr rawFileName,
        [In] ref SECURITY_INFORMATION rawRequestedInformation,
        IntPtr rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        ref uint rawSecurityDescriptorLengthNeeded,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileSecurityDelegate(
        IntPtr rawFileName,
        [In] ref SECURITY_INFORMATION rawSecurityInformation,
        IntPtr rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        in DokanFileInfo rawFileInfo);

    /// <summary>
    /// Retrieve all FileStreams informations on the file.
    /// This is only called if <see cref="DokanOptions.AltStream"/> is enabled.
    /// </summary>
    /// <remarks>Supported since 0.8.0. 
    /// You must specify the version at <see cref="DOKAN_OPTIONS.Version"/>.</remarks>
    /// <param name="rawFileName">Filename</param>
    /// <param name="rawFillFindData">A <see cref="IntPtr"/> to a <see cref="FILL_FIND_STREAM_DATA"/>.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/>.</param>
    /// <returns></returns>
    public delegate NtStatus FindStreamsDelegate(
        IntPtr rawFileName,
        IntPtr rawFillFindData,
        IntPtr findStreamContext,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus MountedDelegate(
        IntPtr rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus UnmountedDelegate(
        in DokanFileInfo rawFileInfo);

#endregion Delegates

    private readonly IDokanOperations operations;

    private readonly ILogger logger;

    private uint serialNumber;

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
    /// Initializes a new instance of the <see cref="DokanOperationProxy"/> class.
    /// </summary>
    /// <param name="operations">
    /// A <see cref="IDokanOperations"/> that contains the custom implementation of the driver.
    /// </param>
    /// <param name="logger">
    /// A <see cref="ILogger"/> that handle all logging.
    /// </param>
    public DokanOperationProxy(IDokanOperations operations, ILogger logger)
    {
        this.operations = operations;
        this.logger = logger;
        serialNumber = (uint)operations.GetHashCode();
    }


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
        IntPtr rawFileName,
        IntPtr securityContext,
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
                SpanFromIntPtr(rawFileName),
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
            return DokanResult.Unsuccessful;
        }
    }

    ////

    public void CleanupProxy(IntPtr rawFileName, ref DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"CleanupProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            operations.Cleanup(SpanFromIntPtr(rawFileName), ref rawFileInfo);

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

    public void CloseFileProxy(IntPtr rawFileName, ref DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"CloseFileProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            operations.CloseFile(SpanFromIntPtr(rawFileName), ref rawFileInfo);

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

    unsafe public NtStatus ReadFileProxy(
        IntPtr rawFileName,
        IntPtr rawBuffer,
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

            // Check if the file system has implemented the unsafe Dokan interface.
            // If so, pass the raw IntPtr through instead of marshaling.
            var result = operations.ReadFile(SpanFromIntPtr(rawFileName), new(rawBuffer.ToPointer(), (int)rawBufferLength), out rawReadLength, rawOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"ReadFileProxy : {rawFileName} Return : {result} ReadLength : {rawReadLength}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"ReadFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    unsafe public NtStatus WriteFileProxy(
        IntPtr rawFileName,
        IntPtr rawBuffer,
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

            // Check if the file system has implemented the unsafe Dokan interface.
            // If so, pass the raw IntPtr through instead of marshalling.
            var result = operations.WriteFile(SpanFromIntPtr(rawFileName), new(rawBuffer.ToPointer(), (int)rawNumberOfBytesToWrite), out rawNumberOfBytesWritten, rawOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"WriteFileProxy : {rawFileName} Return : {result} NumberOfBytesWritten : {rawNumberOfBytesWritten}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"WriteFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus FlushFileBuffersProxy(IntPtr rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FlushFileBuffersProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FlushFileBuffers(SpanFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"FlushFileBuffersProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FlushFileBuffersProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus GetFileInformationProxy(
        IntPtr rawFileName,
        ref BY_HANDLE_FILE_INFORMATION rawHandleFileInformation,
        in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"GetFileInformationProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.GetFileInformation(SpanFromIntPtr(rawFileName), out var fi, rawFileInfo);

            if (result == DokanResult.Success)
            {
                //Debug.Assert(fi.FileName is not null, "FileName must not be null");
                if (logger.DebugEnabled)
                {
                    logger.Debug($"\tFileName\t{rawFileName}");
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
#if NETCOREAPP || NETSTANDARD2_1_OR_GREATER
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
                logger.Debug($"GetFileInformationProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"GetFileInformationProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus FindFilesProxy(IntPtr rawFileName, IntPtr rawFillFindData, in DokanFileInfo rawFileInfo)
    {
        var startTime = Environment.TickCount;

        var fileNamePtr = SpanFromIntPtr(rawFileName);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesProxy : {fileNamePtr.ToString()}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FindFiles(fileNamePtr, out var files, rawFileInfo);

            if (result == DokanResult.Success)
            {
                Debug.Assert(files is not null, "Files must not be null");

                var fill = GetDataFromPointer<FILL_FIND_FILE_DATA>(rawFillFindData);

                var count = 0L;

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files)
                {
                    count++;

                    if (unchecked(Environment.TickCount - startTime) >= 30000)
                    {
                        logger.Error($"FindFilesProxy : Timed out at {fileNamePtr.ToString()} after {count} files");
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

                    AddTo(fill, in rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesProxy : {fileNamePtr.ToString()} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindFilesProxy : {fileNamePtr.ToString()} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    public NtStatus FindFilesWithPatternProxy(
        IntPtr rawFileName,
        IntPtr rawSearchPattern,
        IntPtr rawFillFindData,
        in DokanFileInfo rawFileInfo)
    {
        var startTime = Environment.TickCount;

        var fileNamePtr = SpanFromIntPtr(rawFileName);
        var searchPatternPtr = SpanFromIntPtr(rawSearchPattern);

        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesWithPatternProxy : {fileNamePtr.ToString()}");
                logger.Debug($"\trawSearchPattern\t{searchPatternPtr.ToString()}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            // TODO(someone): Allow userland FS to set FindFiles preference at mount time and nullify the callback not used.
            var result = operations.FindFilesWithPattern(fileNamePtr, searchPatternPtr, out var files, rawFileInfo);

            Debug.Assert(files is not null, "Files must not be null");
            if (result == DokanResult.Success)
            {
                var fill = GetDataFromPointer<FILL_FIND_FILE_DATA>(rawFillFindData);

                var count = 0L;

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files)
                {
                    count++;

                    if (unchecked(Environment.TickCount - startTime) >= 30000)
                    {
                        logger.Error($"FindFilesWithPatternProxy : Timed out at {fileNamePtr.ToString()} with pattern {searchPatternPtr.ToString()} after {count} files");
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

                    AddTo(fill, in rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindFilesWithPatternProxy : {fileNamePtr.ToString()} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindFilesWithPatternProxy : {fileNamePtr.ToString()} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    /// <summary>
    /// Call the delegate <paramref name="fill"/> using data in <paramref name="rawFileInfo"/> and <paramref name="fi"/>.
    /// </summary>
    /// <param name="fill">The delegate of type <see cref="FILL_FIND_FILE_DATA"/> to be called.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/> to be used when calling <paramref name="fill"/>.</param>
    /// <param name="fi">A <see cref="ByHandleFileInformation"/> with information to be used when calling <paramref name="fill"/>.</param>
    private static void AddTo(FILL_FIND_FILE_DATA fill, in DokanFileInfo rawFileInfo, FindFileInformation fi)
    {
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

        fill(ref data, in rawFileInfo);
    }

    public NtStatus FindStreamsProxy(IntPtr rawFileName, IntPtr rawFillFindData, IntPtr findStreamContext, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"FindStreamsProxy: {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.FindStreams(SpanFromIntPtr(rawFileName), out var files, in rawFileInfo);

            Debug.Assert(!(result == DokanResult.NotImplemented && files is null));
            if (result == DokanResult.Success)
            {
                var fill = GetDataFromPointer<FILL_FIND_STREAM_DATA>(rawFillFindData);

                // used a single entry call to speed up the "enumeration" of the list
                foreach (var fi in files)
                {
                    if (logger.DebugEnabled)
                    {
                        logger.Debug($"\tFileName\t{fi.FileName}");
                        logger.Debug($"\t\tLength\t{fi.Length}");
                    }

                    AddTo(fill, in rawFileInfo, fi);
                }
            }

            if (logger.DebugEnabled)
            {
                logger.Debug($"FindStreamsProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"FindStreamsProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    /// <summary>Converts an unmanaged function pointer to a delegate of a specified type. </summary>
    /// <returns>A instance of the specified delegate type.</returns>
    /// <param name="rawDelegate">The unmanaged function pointer to convert. </param>
    /// <typeparam name="TDelegate">The type of the delegate to return. </typeparam>
    /// <exception cref="System.ArgumentException">The <typeparam name="TDelegate" /> generic parameter is not a delegate, or it is an open generic type.</exception>
    /// <exception cref="System.ArgumentNullException">The <paramref name="rawDelegate" /> parameter is null.</exception>
    private static TDelegate GetDataFromPointer<TDelegate>(IntPtr rawDelegate) where TDelegate : class =>
        Marshal.GetDelegateForFunctionPointer<TDelegate>(rawDelegate);


    /// <summary>
    /// Call the delegate <paramref name="fill"/> using data in <paramref name="rawFileInfo"/> and <paramref name="fi"/>.
    /// </summary>
    /// <param name="fill">The delegate of type <see cref="FILL_FIND_STREAM_DATA"/> to be called.</param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/> to be used when calling <paramref name="fill"/>.</param>
    /// <param name="fi">A <see cref="ByHandleFileInformation"/> with information to be used when calling <paramref name="fill"/>.</param>
    private static void AddTo(FILL_FIND_STREAM_DATA fill, in DokanFileInfo rawFileInfo, FindFileInformation fi)
    {
        Debug.Assert(!fi.FileName.IsEmpty, "FileName must not be empty or null");
        var data = new WIN32_FIND_STREAM_DATA
        {
            StreamSize = fi.Length,
            StreamName = fi.FileName.Span
        };
        //ZeroMemory(&data, sizeof(WIN32_FIND_DATAW));

        fill(ref data, in rawFileInfo);
    }

    ////

    public NtStatus SetEndOfFileProxy(IntPtr rawFileName, long rawByteOffset, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetEndOfFileProxy : {rawFileName}");
                logger.Debug($"\tByteOffset\t{rawByteOffset}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetEndOfFile(SpanFromIntPtr(rawFileName), rawByteOffset, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetEndOfFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetEndOfFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    public NtStatus SetAllocationSizeProxy(IntPtr rawFileName, long rawLength, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetAllocationSizeProxy : {rawFileName}");
                logger.Debug($"\tLength\t{rawLength}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetAllocationSize(SpanFromIntPtr(rawFileName), rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetAllocationSizeProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetAllocationSizeProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus SetFileAttributesProxy(IntPtr rawFileName, uint rawAttributes, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileAttributesProxy : {rawFileName}");
                logger.Debug($"\tAttributes\t{(FileAttributes)rawAttributes}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.SetFileAttributes(SpanFromIntPtr(rawFileName), (FileAttributes)rawAttributes, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileAttributesProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileAttributesProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus SetFileTimeProxy(
        IntPtr rawFileName,
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

            var result = operations.SetFileTime(SpanFromIntPtr(rawFileName), ctime, atime, mtime, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileTimeProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileTimeProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus DeleteFileProxy(IntPtr rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteFileProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.DeleteFile(SpanFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"DeleteFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus DeleteDirectoryProxy(IntPtr rawFileName, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteDirectoryProxy : {rawFileName}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.DeleteDirectory(SpanFromIntPtr(rawFileName), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"DeleteDirectoryProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"DeleteDirectoryProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus MoveFileProxy(
        IntPtr rawFileName,
        IntPtr rawNewFileName,
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

            var result = operations.MoveFile(SpanFromIntPtr(rawFileName), SpanFromIntPtr(rawNewFileName), rawReplaceIfExisting, ref rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"MoveFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"MoveFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus LockFileProxy(IntPtr rawFileName, long rawByteOffset, long rawLength, in DokanFileInfo rawFileInfo)
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

            var result = operations.LockFile(SpanFromIntPtr(rawFileName), rawByteOffset, rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"LockFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"LockFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
        }
    }

    ////

    public NtStatus UnlockFileProxy(
        IntPtr rawFileName,
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

            var result = operations.UnlockFile(SpanFromIntPtr(rawFileName), rawByteOffset, rawLength, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"UnlockFileProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"UnlockFileProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
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
            return DokanResult.InvalidParameter;
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
            return DokanResult.InvalidParameter;
        }
    }

    public NtStatus MountedProxy(IntPtr mountPoint, in DokanFileInfo rawFileInfo)
    {
        try
        {
            if (logger.DebugEnabled)
            {
                logger.Debug($"MountedProxy:");
                logger.Debug($"\tMountPoint\t{mountPoint}");
                logger.Debug($"\tContext\t{rawFileInfo}");
            }

            var result = operations.Mounted(SpanFromIntPtr(mountPoint), rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"MountedProxy Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"MountedProxy Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
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
            return DokanResult.InvalidParameter;
        }
    }

    public NtStatus GetFileSecurityProxy(
        IntPtr rawFileName,
        ref SECURITY_INFORMATION rawRequestedInformation,
        IntPtr rawSecurityDescriptor,
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

            var result = operations.GetFileSecurity(SpanFromIntPtr(rawFileName), out var sec, sect, rawFileInfo);
            if (result == DokanResult.Success /*&& sec is not null*/)
            {
                Debug.Assert(sec is not null, $"{nameof(sec)} must not be null");
                if (logger.DebugEnabled)
                {
                    logger.Debug($"\tFileSystemSecurity Result : {sec}");
                }

                var buffer = sec.GetSecurityDescriptorBinaryForm();
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
            return DokanResult.InvalidParameter;
        }
    }

    public NtStatus SetFileSecurityProxy(
        IntPtr rawFileName,
        ref SECURITY_INFORMATION rawSecurityInformation,
        IntPtr rawSecurityDescriptor,
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

            var result = operations.SetFileSecurity(SpanFromIntPtr(rawFileName), sec, sect, rawFileInfo);

            if (logger.DebugEnabled)
            {
                logger.Debug($"SetFileSecurityProxy : {rawFileName} Return : {result}");
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.Error($"SetFileSecurityProxy : {rawFileName} Throw : {ex.Message}");
            return DokanResult.InvalidParameter;
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
    private static long ToFileTime(DateTime? dateTime)
    {
        return dateTime.HasValue && (dateTime.Value >= DateTime.FromFileTime(0))
            ? dateTime.Value.ToFileTime()
            : 0;
    }

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
