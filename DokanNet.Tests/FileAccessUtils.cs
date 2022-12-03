using System;
using System.Linq;

namespace DokanNet.Tests;

static class FileAccessUtils
{
    private const NativeFileAccess FILE_GENERIC_READ =
        NativeFileAccess.ReadAttributes |
        NativeFileAccess.ReadData |
        NativeFileAccess.ReadExtendedAttributes |
        NativeFileAccess.ReadPermissions |
        NativeFileAccess.Synchronize;

    private const NativeFileAccess FILE_GENERIC_WRITE =
        NativeFileAccess.AppendData |
        NativeFileAccess.WriteAttributes |
        NativeFileAccess.WriteData |
        NativeFileAccess.WriteExtendedAttributes |
        NativeFileAccess.ReadPermissions |
        NativeFileAccess.Synchronize;

    private const NativeFileAccess FILE_GENERIC_EXECUTE =
        NativeFileAccess.Execute |
        NativeFileAccess.ReadAttributes |
        NativeFileAccess.ReadPermissions |
        NativeFileAccess.Synchronize;

    private static readonly NativeFileAccess FILE_ALL_ACCESS = (NativeFileAccess)Enum.GetValues(typeof(NativeFileAccess)).Cast<long>().Sum();

    public static NativeFileAccess MapSpecificToGenericAccess(NativeFileAccess desiredAccess)
    {
        var outDesiredAccess = desiredAccess;

        var genericRead = false;
        var genericWrite = false;
        var genericExecute = false;
        var genericAll = false;
        if ((outDesiredAccess & FILE_GENERIC_READ) == FILE_GENERIC_READ)
        {
            outDesiredAccess |= NativeFileAccess.GenericRead;
            genericRead = true;
        }

        if ((outDesiredAccess & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
        {
            outDesiredAccess |= NativeFileAccess.GenericWrite;
            genericWrite = true;
        }

        if ((outDesiredAccess & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
        {
            outDesiredAccess |= NativeFileAccess.GenericExecute;
            genericExecute = true;
        }

        if ((outDesiredAccess & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
        {
            outDesiredAccess |= NativeFileAccess.GenericAll;
            genericAll = true;
        }

        if (genericRead)
        {
            outDesiredAccess &= ~FILE_GENERIC_READ;
        }

        if (genericWrite)
        {
            outDesiredAccess &= ~FILE_GENERIC_WRITE;
        }

        if (genericExecute)
        {
            outDesiredAccess &= ~FILE_GENERIC_EXECUTE;
        }

        if (genericAll)
        {
            outDesiredAccess &= ~FILE_ALL_ACCESS;
        }

        return outDesiredAccess;
    }
}
