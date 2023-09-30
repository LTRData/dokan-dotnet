using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
using System.Text;

namespace DokanNet.Native;

/// <summary>
/// Dokan API callbacks interface
/// 
/// A struct of callbacks that describe all Dokan API operation
/// that will be called when Windows access to the filesystem.
/// 
/// If an error occurs, return <see cref="NtStatus"/>.
/// 
/// All this callbacks can be set to <c>null</c> or return <see cref="NtStatus.NotImplemented"/>
/// if you dont want to support one of them. Be aware that returning such value to important callbacks
/// such <see cref="ZwCreateFile"/>/<see cref="ReadFile"/>/... would make the filesystem not working or unstable.
/// 
/// Se <see cref="IDokanOperations"/> for more information about the fields.
/// </summary>
/// <remarks>This is the same struct as <c>_DOKAN_OPERATIONS</c> (dokan.h) in the C version of Dokan.</remarks>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal sealed class DOKAN_OPERATIONS
{
    #region Delegates

    public delegate NtStatus ZwCreateFileDelegate(
        nint rawFileName,
        nint securityContext,
        uint rawDesiredAccess,
        uint rawFileAttributes,
        uint rawShareAccess,
        uint rawCreateDisposition,
        uint rawCreateOptions,
        ref DokanFileInfo dokanFileInfo);

    public delegate void CleanupDelegate(
        nint rawFileName,
        ref DokanFileInfo rawFileInfo);

    public delegate void CloseFileDelegate(
        nint rawFileName,
        ref DokanFileInfo rawFileInfo);

    public delegate NtStatus ReadFileDelegate(
        nint rawFileName,
        nint rawBuffer,
        uint rawBufferLength,
        ref int rawReadLength,
        long rawOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus WriteFileDelegate(
        nint rawFileName,
        nint rawBuffer,
        uint rawNumberOfBytesToWrite,
        ref int rawNumberOfBytesWritten,
        long rawOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus FlushFileBuffersDelegate(
        nint rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus GetFileInformationDelegate(
        nint rawFileName,
        ref BY_HANDLE_FILE_INFORMATION handleFileInfo,
        in DokanFileInfo fileInfo);

    public delegate NtStatus FindFilesDelegate(
        nint rawFileName,
        nint rawFillFindData,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus FindFilesWithPatternDelegate(
        nint rawFileName,
        nint rawSearchPattern,
        nint rawFillFindData,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileAttributesDelegate(
        nint rawFileName,
        uint rawAttributes,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileTimeDelegate(
        nint rawFileName,
        ref FILETIME rawCreationTime,
        ref FILETIME rawLastAccessTime,
        ref FILETIME rawLastWriteTime,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus DeleteFileDelegate(
        nint rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus DeleteDirectoryDelegate(
        nint rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus MoveFileDelegate(
        nint rawFileName,
        nint rawNewFileName,
        [MarshalAs(UnmanagedType.Bool)] bool rawReplaceIfExisting,
        ref DokanFileInfo rawFileInfo);

    public delegate NtStatus SetEndOfFileDelegate(
        nint rawFileName,
        long rawByteOffset,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetAllocationSizeDelegate(
        nint rawFileName,
        long rawLength,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus LockFileDelegate(
        nint rawFileName,
        long rawByteOffset, long rawLength,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus UnlockFileDelegate(
        nint rawFileName,
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
        nint rawFileName,
        [In] ref SECURITY_INFORMATION rawRequestedInformation,
        nint rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        ref uint rawSecurityDescriptorLengthNeeded,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus SetFileSecurityDelegate(
        nint rawFileName,
        [In] ref SECURITY_INFORMATION rawSecurityInformation,
        nint rawSecurityDescriptor,
        uint rawSecurityDescriptorLength,
        in DokanFileInfo rawFileInfo);

    /// <summary>
    /// Retrieve all FileStreams informations on the file.
    /// This is only called if <see cref="DokanOptions.AltStream"/> is enabled.
    /// </summary>
    /// <remarks>Supported since 0.8.0. 
    /// You must specify the version at <see cref="DOKAN_OPTIONS.Version"/>.</remarks>
    /// <param name="rawFileName">Filename</param>
    /// <param name="rawFillFindData">A <see cref="nint"/> to a <see cref="WIN32_FIND_STREAM_DATA"/>.</param>
    /// <param name="findStreamContext"></param>
    /// <param name="rawFileInfo">A <see cref="DokanFileInfo"/>.</param>
    /// <returns></returns>
    public delegate NtStatus FindStreamsDelegate(
        nint rawFileName,
        nint rawFillFindData,
        nint findStreamContext,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus MountedDelegate(
        nint rawFileName,
        in DokanFileInfo rawFileInfo);

    public delegate NtStatus UnmountedDelegate(
        in DokanFileInfo rawFileInfo);

    #endregion Delegates

    public ZwCreateFileDelegate ZwCreateFile = null!;
    public CleanupDelegate Cleanup = null!;
    public CloseFileDelegate CloseFile = null!;
    public ReadFileDelegate ReadFile = null!;
    public WriteFileDelegate WriteFile = null!;
    public FlushFileBuffersDelegate FlushFileBuffers = null!;
    public GetFileInformationDelegate GetFileInformation = null!;
    public FindFilesDelegate FindFiles = null!;

    public FindFilesWithPatternDelegate FindFilesWithPattern = null!;

    public SetFileAttributesDelegate SetFileAttributes = null!;
    public SetFileTimeDelegate SetFileTime = null!;
    public DeleteFileDelegate DeleteFile = null!;
    public DeleteDirectoryDelegate DeleteDirectory = null!;
    public MoveFileDelegate MoveFile = null!;
    public SetEndOfFileDelegate SetEndOfFile = null!;
    public SetAllocationSizeDelegate SetAllocationSize = null!;

    // Lockfile & Unlockfile are only used if dokan option UserModeLock is enabled
    public LockFileDelegate LockFile = null!;
    public UnlockFileDelegate UnlockFile = null!;

    public GetDiskFreeSpaceDelegate GetDiskFreeSpace = null!;
    public GetVolumeInformationDelegate GetVolumeInformation = null!;
    public MountedDelegate Mounted = null!;
    public UnmountedDelegate Unmounted = null!;

    public GetFileSecurityDelegate GetFileSecurity = null!;
    public SetFileSecurityDelegate SetFileSecurity = null!;

    public FindStreamsDelegate FindStreams = null!;
}
