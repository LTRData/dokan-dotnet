﻿using DokanNet.Native;
using System;
using System.Buffers;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0057 // Use range operator

namespace DokanNet;

/// <summary>
/// %Dokan functions helpers for user <see cref="IDokanOperations"/> implementation.
/// </summary>
public static class DokanHelper
{
    /// <summary>
    /// Matches zero or more characters until encountering and matching the final . in the name.
    /// </summary>
    private const char DOS_STAR = '<';

    /// <summary>
    /// Matches any single character or, upon encountering a period or end
    /// of name string, advances the expression to the end of the set of
    /// contiguous DOS_QMs.
    /// </summary>
    private const char DOS_QM = '>';

    /// <summary>
    /// Matches either a period or zero characters beyond the name string.
    /// </summary>
    private const char DOS_DOT = '"';

    /// <summary>
    /// Matches zero or more characters.
    /// </summary>
    private const char ASTERISK = '*';

    /// <summary>
    /// Matches a single character.
    /// </summary>
    private const char QUESTION_MARK = '?';

    private readonly static char[] CharsThatMatchEmptyStringsAtEnd = [DOS_DOT, DOS_STAR, ASTERISK];

    /// <summary>
    /// Check whether <paramref name="name">Name</paramref> matches <paramref name="expression">Expression</paramref>.
    /// </summary>
    /// <remarks>
    /// This method is mainly used in <see cref="IDokanOperations.FindFilesWithPattern"/> to filter a list of possible files.
    /// For example "F0_&lt;&quot;*" match "f0_001.txt"
    /// \see <a href="http://msdn.microsoft.com/en-us/library/ff546850(v=VS.85).aspx">See FsRtlIsNameInExpression routine (MSDN)</a>
    /// </remarks>
    /// <param name="expression">The matching pattern. Can contain: ?, *, &lt;, &quot;, &gt;.</param>
    /// <param name="name">The string that will be tested.</param>
    /// <param name="ignoreCase">When set to true a case insensitive match will be performed.</param>
    /// <returns>Returns true if Expression match Name, false otherwise.</returns>
    public static bool DokanIsNameInExpression(ReadOnlySpan<char> expression, ReadOnlySpan<char> name, bool ignoreCase)
    {
        var ei = 0;
        var ni = 0;

        while (ei < expression.Length && ni < name.Length)
        {
            switch (expression[ei])
            {
                case ASTERISK:
                    ei++;
                    if (ei > expression.Length)
                    {
                        return true;
                    }

                    while (ni < name.Length)
                    {
                        if (DokanIsNameInExpression(expression.Slice(ei), name.Slice(ni), ignoreCase))
                        {
                            return true;
                        }

                        ni++;
                    }

                    break;
                case DOS_STAR:
                    var lastDotIndex = name.LastIndexOf('.');
                    ei++;

                    var endReached = false;
                    while (!endReached)
                    {
                        endReached = ni >= name.Length || lastDotIndex > -1 && ni > lastDotIndex;

                        if (!endReached)
                        {
                            if (DokanIsNameInExpression(expression.Slice(ei), name.Slice(ni), ignoreCase))
                            {
                                return true;
                            }

                            ni++;
                        }
                    }

                    break;
                case DOS_QM:
                    ei++;
                    if (name[ni] != '.')
                    {
                        ni++;
                    }
                    else
                    {
                        var p = ni + 1;
                        while (p < name.Length)
                        {
                            if (name[p] == '.')
                            {
                                break;
                            }

                            p++;
                        }

                        if (p < name.Length && name[p] == '.')
                        {
                            ni++;
                        }
                    }

                    break;
                case DOS_DOT:
                    if (ei < expression.Length)
                    {
                        if (name[ni] != '.')
                        {
                            return false;
                        }
                        else
                        {
                            ni++;
                        }
                    }
                    else
                    {
                        if (name[ni] == '.')
                        {
                            ni++;
                        }
                    }

                    ei++;
                    break;
                case QUESTION_MARK:
                    ei++;
                    ni++;
                    break;
                default:
                    if (ignoreCase && char.ToUpperInvariant(expression[ei]) == char.ToUpperInvariant(name[ni]))
                    {
                        ei++;
                        ni++;
                    }
                    else if (!ignoreCase && expression[ei] == name[ni])
                    {
                        ei++;
                        ni++;
                    }
                    else
                    {
                        return false;
                    }

                    break;
            }
        }

        var nextExpressionChars = expression.Slice(ei);

        var areNextExpressionCharsAllNullMatchers = false;

        if (!expression.IsEmpty &&
            !nextExpressionChars.IsEmpty)
        {
            areNextExpressionCharsAllNullMatchers = true;

            foreach (var chr in nextExpressionChars)
            {
                if (Array.IndexOf(CharsThatMatchEmptyStringsAtEnd, chr) < 0)
                {
                    areNextExpressionCharsAllNullMatchers = false;
                    break;
                }
            }
        }

        var isNameCurrentCharTheLast = ni == name.Length;

        if (ei == expression.Length && isNameCurrentCharTheLast || isNameCurrentCharTheLast && areNextExpressionCharsAllNullMatchers)
        {
            return true;
        }

        return false;
    }

    public static string GetStringFromSpan(ReadOnlySpan<char> span)
    {
        if (span.IsEmpty)
        {
            return "";
        }
        else if (span.Equals("/".AsSpan(), StringComparison.Ordinal))
        {
            return "/";
        }
        else if (span.Equals(@"\".AsSpan(), StringComparison.Ordinal))
        {
            return @"\";
        }
        else if (span.Equals("*".AsSpan(), StringComparison.Ordinal))
        {
            return "*";
        }
        else if (span.Equals("*.*".AsSpan(), StringComparison.Ordinal))
        {
            return "*.*";
        }
        else if (span.Equals("?".AsSpan(), StringComparison.Ordinal))
        {
            return "?";
        }
        else if (span.Equals(@"\Desktop.ini".AsSpan(), StringComparison.Ordinal))
        {
            return @"\Desktop.ini";
        }
        else if (span.Equals(@"\desktop.ini".AsSpan(), StringComparison.Ordinal))
        {
            return @"\desktop.ini";
        }
        else if (span.Equals(@"\AutoRun.inf".AsSpan(), StringComparison.Ordinal))
        {
            return @"\AutoRun.inf";
        }
        else
        {
            return span.ToString();
        }
    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public static NtStatus ToNtStatus(this Exception? ex)
    {
        while (ex is TargetInvocationException or AggregateException)
        {
#pragma warning disable CA1062 // Validate arguments of public methods
            ex = ex.InnerException;
#pragma warning restore CA1062 // Validate arguments of public methods
        }

        if (ex is null)
        {
            return NtStatus.Unsuccessful;
        }
        
        if (ex is Win32Exception win32Exception)
        {
            return NativeMethods.DokanNtStatusFromWin32(win32Exception.NativeErrorCode);
        }

        if ((unchecked((uint)ex.HResult) & 0xffff0000) == 0x80070000)
        {
            return NativeMethods.DokanNtStatusFromWin32(ex.HResult & 0xffff);
        }

        // First try to match types directly, then normalize from hresult
        var status = ex switch
        {
            InvalidOperationException => NtStatus.NotImplemented,
            NotSupportedException or NotImplementedException => NtStatus.NotImplemented,
            ThreadAbortException or ThreadInterruptedException or OperationCanceledException => NtStatus.Cancelled,
            ArgumentOutOfRangeException or IndexOutOfRangeException or
                ArgumentNullException or NullReferenceException => NtStatus.InvalidParameter,
            _ => unchecked((uint)ex.HResult) switch
            {
                0x80131509 => NtStatus.NotImplemented,
                0x80131515 or 0x80131509 => NtStatus.NotImplemented,
                0x80131519 or 0x8013153B => NtStatus.Cancelled,
                0x80131502 or 0x80131508 or 0x80004003 or 0x80004003 => NtStatus.InvalidParameter,
                _ => NtStatus.Unsuccessful
            }
        };

        return status;
    }

    /// <summary>
    /// Copies characters from a <see cref="string"/> to a <see cref="Span{Char}"/>,
    /// clearing remainder of the target memory if larger than the source string. If source is
    /// longer than target buffer size, target receives a truncated version of source string.
    /// </summary>
    /// <param name="buffer">Target buffer</param>
    /// <param name="str">Source string to copy to buffer</param>
    public static void SetString(this Span<char> buffer, string? str)
        => SetString(buffer, str.AsSpan());

    /// <summary>
    /// Copies characters from a <see cref="ReadOnlySpan{Char}"/> to a <see cref="Span{Char}"/>,
    /// clearing remainder of the target memory if larger than the source string. If source is
    /// longer than target buffer size, target receives a truncated version of source string.
    /// </summary>
    /// <param name="buffer">Target buffer</param>
    /// <param name="str">Source string to copy to buffer</param>
    public static void SetString(this Span<char> buffer, ReadOnlySpan<char> str)
    {
        if (str.IsEmpty)
        {
            buffer.Clear();
        }
        else if (str.Length < buffer.Length)
        {
            str.CopyTo(buffer);
            buffer.Slice(str.Length).Clear();
        }
        else
        {
            str.Slice(0, buffer.Length).CopyTo(buffer);
        }
    }

    /// <summary>
    /// Copies characters from a <see cref="string"/> to a <see cref="DokanMemory{Char}"/>,
    /// clearing remainder of the target memory if larger than the source string. If source is
    /// longer than target buffer size, target receives a truncated version of source string.
    /// </summary>
    /// <param name="buffer">Target buffer</param>
    /// <param name="str">Source string to copy to buffer</param>
    public static void SetString(this DokanMemory<char> buffer, string? str)
        => SetString(buffer.Span, str.AsSpan());

    /// <summary>
    /// Copies characters from a <see cref="ReadOnlySpan{Char}"/> to a <see cref="DokanMemory{Char}"/>,
    /// clearing remainder of the target memory if larger than the source string. If source is
    /// longer than target buffer size, target receives a truncated version of source string.
    /// </summary>
    /// <param name="buffer">Target buffer</param>
    /// <param name="str">Source string to copy to buffer</param>
    public static void SetString(this DokanMemory<char> buffer, ReadOnlySpan<char> str)
        => SetString(buffer.Span, str);

#if NETFRAMEWORK || (NETSTANDARD && !NETSTANDARD2_1_OR_GREATER)
    public static int Read(this Stream stream, Span<byte> buffer)
    {
        var array = ArrayPool<byte>.Shared.Rent(buffer.Length);
        try
        {
            var count = stream.Read(array, 0, buffer.Length);
            array.AsSpan(0, count).CopyTo(buffer);
            return count;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(array);
        }
    }

    public static void Write(this Stream stream, ReadOnlySpan<byte> buffer)
    {
        var array = ArrayPool<byte>.Shared.Rent(buffer.Length);
        try
        {
            buffer.CopyTo(array);
            stream.Write(array, 0, buffer.Length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(array);
        }
    }
#endif
}
