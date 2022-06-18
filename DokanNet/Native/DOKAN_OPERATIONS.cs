﻿using System;
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

    public ZwCreateFileDelegate ZwCreateFile;
    public CleanupDelegate Cleanup;
    public CloseFileDelegate CloseFile;
    public ReadFileDelegate ReadFile;
    public WriteFileDelegate WriteFile;
    public FlushFileBuffersDelegate FlushFileBuffers;
    public GetFileInformationDelegate GetFileInformation;
    public FindFilesDelegate FindFiles;

    public FindFilesWithPatternDelegate FindFilesWithPattern;

    public SetFileAttributesDelegate SetFileAttributes;
    public SetFileTimeDelegate SetFileTime;
    public DeleteFileDelegate DeleteFile;
    public DeleteDirectoryDelegate DeleteDirectory;
    public MoveFileDelegate MoveFile;
    public SetEndOfFileDelegate SetEndOfFile;
    public SetAllocationSizeDelegate SetAllocationSize;

    // Lockfile & Unlockfile are only used if dokan option UserModeLock is enabled
    public LockFileDelegate LockFile;
    public UnlockFileDelegate UnlockFile;

    public GetDiskFreeSpaceDelegate GetDiskFreeSpace;
    public GetVolumeInformationDelegate GetVolumeInformation;
    public MountedDelegate Mounted;
    public UnmountedDelegate Unmounted;

    public GetFileSecurityDelegate GetFileSecurity;
    public SetFileSecurityDelegate SetFileSecurity;

    public FindStreamsDelegate FindStreams;
}
