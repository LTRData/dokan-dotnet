using System.IO;

namespace DokanNet.Tests;

internal static class FileSettings
{
    public const NativeFileAccess ReadAttributesAccess = NativeFileAccess.ReadAttributes;

    public const NativeFileAccess ReadPermissionsAccess = NativeFileAccess.ReadPermissions;

    public const NativeFileAccess ReadAttributesPermissionsAccess = ReadAttributesAccess | ReadPermissionsAccess;

    public const NativeFileAccess ChangePermissionsAccess = NativeFileAccess.ReadAttributes | NativeFileAccess.ReadPermissions | NativeFileAccess.ChangePermissions;

    public const NativeFileAccess ReadAccess = NativeFileAccess.ReadData | NativeFileAccess.ReadExtendedAttributes | NativeFileAccess.ReadAttributes | NativeFileAccess.ReadPermissions | NativeFileAccess.Synchronize;

    public const NativeFileAccess WriteAccess =
        NativeFileAccess.WriteData | NativeFileAccess.AppendData | NativeFileAccess.WriteExtendedAttributes |
        NativeFileAccess.ReadAttributes | NativeFileAccess.WriteAttributes | NativeFileAccess.ReadPermissions | NativeFileAccess.Synchronize;

    public const NativeFileAccess ReadWriteAccess = ReadAccess | WriteAccess;

    public const NativeFileAccess SetOwnershipAccess = ReadAccess | WriteAccess | NativeFileAccess.Delete | NativeFileAccess.ChangePermissions | NativeFileAccess.SetOwnership;

    public const NativeFileAccess DeleteAccess = NativeFileAccess.ReadAttributes | NativeFileAccess.Delete;

    public const NativeFileAccess CopyToAccess = ReadAccess | WriteAccess | NativeFileAccess.Delete | NativeFileAccess.ChangePermissions;

    public const NativeFileAccess MoveFromAccess = NativeFileAccess.ReadAttributes | NativeFileAccess.Delete | NativeFileAccess.Synchronize;

    public const NativeFileAccess ReplaceAccess = NativeFileAccess.WriteData | NativeFileAccess.ReadExtendedAttributes | NativeFileAccess.ReadAttributes | NativeFileAccess.Delete | NativeFileAccess.ReadPermissions | NativeFileAccess.Synchronize;

    public const NativeFileAccess OpenDirectoryAccess = NativeFileAccess.Synchronize;

    public const NativeFileAccess ReadDirectoryAccess = NativeFileAccess.ReadData | NativeFileAccess.Synchronize;

    public const NativeFileAccess WriteDirectoryAccess = NativeFileAccess.WriteData | NativeFileAccess.Synchronize;

    public const NativeFileAccess AppendToDirectoryAccess = NativeFileAccess.AppendData | NativeFileAccess.Synchronize;

    public const NativeFileAccess DeleteFromDirectoryAccess = NativeFileAccess.Delete | NativeFileAccess.ReadAttributes | NativeFileAccess.Synchronize;

    public const FileShare ReadOnlyShare = FileShare.Read;

    public const FileShare ReadShare = FileShare.Read | FileShare.Delete;

    public const FileShare ReadWriteShare = FileShare.ReadWrite | FileShare.Delete;

    public const FileShare WriteShare = FileShare.None;

    public const FileShare OpenDirectoryShare = FileShare.None;

    public const FileOptions ReadFileOptions = FileOptions.None;

    public const FileOptions WriteFileOptions = FileOptions.None;

    public const FileOptions OpenReparsePointOptions = (FileOptions) 0x00200000;

    public const FileOptions OpenNoBufferingOptions = (FileOptions) 0x20000000;
}