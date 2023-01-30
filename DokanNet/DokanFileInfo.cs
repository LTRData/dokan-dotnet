using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Principal;
using DokanNet.Native;
using Microsoft.Win32.SafeHandles;
using static DokanNet.FormatProviders;

namespace DokanNet;

/// <summary>
/// %Dokan file information on the current operation.
/// </summary>
/// <remarks>
/// This class cannot be instantiated in C#, it is created by the kernel %Dokan driver.
/// This is the same structure as <c>_DOKAN_FILE_INFO</c> (dokan.h) in the C version of Dokan.
/// </remarks>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct DokanFileInfo
{
    private long context;

    /// <summary>
    /// Used internally, never modify.
    /// </summary>
    private readonly ulong dokanContext;

    /// <summary>
    /// A pointer to the <see cref="DOKAN_OPTIONS"/> which was passed to <see cref="DokanNet.Native.NativeMethods.DokanMain"/>.
    /// </summary>
    private readonly nint dokanOptions;

    /// <summary>
    /// Reserved. Used internally by Dokan library. Never modify.
    /// If the processing for the event requires extra data to be associated with it
    /// then a pointer to that data can be placed here
    /// </summary>
    private readonly nint processingContext;

    /// <summary>
    /// Process id for the thread that originally requested a given I/O
    /// operation.
    /// </summary>
    public int ProcessId { get; }

    /// <summary>
    /// Gets or sets a value indicating whether it requesting a directory
    /// file. Must be set in <see cref="IDokanOperations.CreateFile"/> if
    /// the file appear to be a folder.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool IsDirectory { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the file has to be delete
    /// during the <see cref="IDokanOperations.Cleanup"/> event.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool DeleteOnClose { get; set; }

    /// <summary>
    /// Read or write is paging IO.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool PagingIo { get; set; }

    /// <summary>
    /// Read or write is synchronous IO.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool SynchronousIo { get; set; }

    /// <summary>
    /// Read or write directly from data source without cache.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool NoCache { get; set; }

    /// <summary>
    /// If <c>true</c>, write to the current end of file instead 
    /// of using the <c>Offset</c> parameter.
    /// </summary>
    [field: MarshalAs(UnmanagedType.U1)] public bool WriteToEndOfFile { get; set; }

    /// <summary>
    /// Gets or sets context that can be used to carry information between operation.
    /// The Context can carry whatever type like <c><see cref="System.IO.FileStream"/></c>, <c>struct</c>, <c>int</c>,
    /// or internal reference that will help the implementation understand the request context of the event.
    /// </summary>
    public object Context
    {
        get
        {
            if (context != 0)
            {
                return ((GCHandle)(nint)context).Target;
            }

            return null;
        }

        set
        {
            if (context != 0)
            {
                ((GCHandle)(nint)context).Free();
                context = 0;
            }

            if (value != null)
            {
                context = (nint)GCHandle.Alloc(value);
            }
        }
    }

    /// <summary>
    /// This method needs to be called in <see cref="IDokanOperations.CreateFile"/>.
    /// </summary>
    /// <returns>An <c><see cref="WindowsIdentity"/></c> with the access token, 
    /// -or- <c>null</c> if the operation was not successful.</returns>
    public WindowsIdentity GetRequestor()
    {
        try
        {
            using var sfh = NativeMethods.DokanOpenRequestorToken(ref this);

            return new(sfh.DangerousGetHandle());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Extends the time out of the current IO operation in driver.
    /// </summary>
    /// <param name="milliseconds">Number of milliseconds to extend with.</param>
    /// <returns>If the operation was successful.</returns>
    public bool TryResetTimeout(int milliseconds) => NativeMethods.DokanResetTimeout((uint)milliseconds, ref this);

    /// <summary>Returns a string that represents the current object.</summary>
    /// <returns>A string that represents the current object.</returns>
    public override string ToString() => DokanFormat(
                $"{{{Context}, {DeleteOnClose}, {IsDirectory}, {NoCache}, {PagingIo}, #{ProcessId}, {SynchronousIo}, {WriteToEndOfFile}}}");
}
