using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using DiscUtils;
using DiscUtils.Dokan;
using DiscUtils.Streams;
using DiscUtils.VirtualFileSystem;
using DokanNet;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0057 // Use range operator

namespace DiscUtilsFs;

internal static class DiscUtilsSupport
{
    private static readonly Assembly[] asms =
    {
        typeof(DiscUtils.Btrfs.BtrfsFileSystem).Assembly,
        typeof(DiscUtils.Ext.ExtFileSystem).Assembly,
        typeof(DiscUtils.Fat.FatFileSystem).Assembly,
        typeof(DiscUtils.HfsPlus.HfsPlusFileSystem).Assembly,
        typeof(DiscUtils.Iso9660.CDReader).Assembly,
        typeof(DiscUtils.Lvm.LogicalVolumeManager).Assembly,
        typeof(DiscUtils.Nfs.NfsFileSystem).Assembly,
        typeof(DiscUtils.Ntfs.NtfsFileSystem).Assembly,
        typeof(DiscUtils.Registry.RegistryHive).Assembly,
        typeof(DiscUtils.SquashFs.SquashFileSystemReader).Assembly,
        typeof(DiscUtils.Swap.SwapFileSystem).Assembly,
        typeof(DiscUtils.Udf.UdfReader).Assembly,
        typeof(DiscUtils.Vdi.Disk).Assembly,
        typeof(DiscUtils.Vhd.Disk).Assembly,
        typeof(DiscUtils.Vhdx.Disk).Assembly,
        typeof(DiscUtils.VirtualFileSystem.TarFileSystem).Assembly,
        typeof(DiscUtils.Wim.WimFileSystem).Assembly,
        typeof(DiscUtils.Vmdk.Disk).Assembly,
        typeof(DiscUtils.Xfs.XfsFileSystem).Assembly,
        typeof(ExFat.DiscUtils.ExFatFileSystem).Assembly
    };

    public static void RegisterAssemblies()
    {
        foreach (var asm in asms.Distinct())
        {
            DiscUtils.Setup.SetupHelper.RegisterAssembly(asm);
        }
    }
}

public static class Program
{
    private const string VhdKey = "-vhd";
    private const string PartKey = "-part";
    private const string FsKey = "-fs";
    private const string MountKey = "-where";
    private const string TmpKey = "-tmp";
    private const string HiddenKey = "-hidden";
    private const string NoExecKey = "-noexec";

    public static int Main(params string[] args)
    {
        try
        {
            Dokan.Init();

            DiscUtilsSupport.RegisterAssemblies();

            var arguments = args
               .Select(x =>
               {
                   var pos = x.IndexOf('=');

                   if (pos < 0)
                   {
                       return new KeyValuePair<string, string>(x, null);
                   }
                   else
                   {
                       return new KeyValuePair<string, string>(x.Remove(pos), x.Substring(pos + 1));
                   }
               })
               .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);

            if (!arguments.TryGetValue(MountKey, out var mountPath))
            {
                mountPath = @"N:\";
            }

            IFileSystem file_system;

            if (arguments.TryGetValue(VhdKey, out var vhdPath))
            {
                file_system = InitializeFromVhd(arguments, vhdPath);
            }
            else if (arguments.TryGetValue(FsKey, out var fsPath))
            {
                file_system = InitializeFromFsImage(fsPath);
            }
            else if (arguments.ContainsKey(TmpKey))
            {
                file_system = InitializeTmpFs();
            }
            else
            {
                Console.WriteLine("Syntax:\r\n" +
                    "DiscUtilsFs [where=drive:] -tmp\r\n" +
                    "DiscUtilsFs [where=drive:] -vhd=image [part=number]\r\n" +
                    "DiscUtilsFs [where=drive:] -fs=image");

                return -1;
            }

            if (file_system == null)
            {
                Console.WriteLine($"No supported file system found.");
                return 1;
            }

            Console.WriteLine($"Found file system, type {file_system.GetType().Name}");

            if (file_system is DiscUtils.Ntfs.NtfsFileSystem ntfs)
            {
                ntfs.NtfsOptions.HideHiddenFiles = false;
                ntfs.NtfsOptions.HideMetafiles = false;
                ntfs.NtfsOptions.HideSystemFiles = false;
            }

            DokanDiscUtilsOptions discutils_options = default;

            if (arguments.ContainsKey(HiddenKey))
            {
                discutils_options |= DokanDiscUtilsOptions.HiddenAsNormal;
            }

            if (arguments.ContainsKey(NoExecKey))
            {
                discutils_options |= DokanDiscUtilsOptions.BlockExecute;
            }

            using var dokan_discutils = new DokanDiscUtils(file_system, discutils_options);

            var mountOptions = default(DokanOptions);

#if DEBUG
            mountOptions |= DokanOptions.DebugMode;
#endif

            if (dokan_discutils.ReadOnly)
            {
                mountOptions |= DokanOptions.WriteProtection;
            }

            if (dokan_discutils.NamedStreams)
            {
                mountOptions |= DokanOptions.AltStream;
            }

            var drive = new DriveInfo(mountPath);

            Console.CancelKeyPress += (sender, e) =>
            {
                if (!dokan_discutils.IsDisposed && drive.IsReady)
                {
                    e.Cancel = true;

                    Console.WriteLine("Dismounting...");

                    Dokan.RemoveMountPoint(mountPath);
                }
            };

            ThreadPool.QueueUserWorkItem(o =>
            {
                try
                {
                    while (!dokan_discutils.IsDisposed && !drive.IsReady)
                    {
                        Thread.Sleep(200);
                    }

                    if (drive.IsReady)
                    {
                        Process.Start(new ProcessStartInfo(mountPath) { UseShellExecute = true });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to open Explorer window: {ex.Message}");
                }
            });

            Console.WriteLine("Press Ctrl+C to dismount.");

            dokan_discutils.Mount(mountPath, mountOptions);

            Console.WriteLine("Dismounted.");

            return 0;
        }
        catch (DokanException ex)
        {
            Console.WriteLine($@"Error: {ex.Message}");

            return ex.HResult;
        }
        finally
        {
            Dokan.Shutdown();
        }
    }

    private static IFileSystem InitializeTmpFs()
    {
        IFileSystem file_system;

        var vfs = new VirtualFileSystem(new VirtualFileSystemOptions
        {
            HasSecurity = false,
            IsThreadSafe = false,
            VolumeLabel = "VirtualFs"
        });

#if SAMPLE_FILE
                    var stream = new MemoryStream();
                    var bytes = Encoding.ASCII.GetBytes("HELLO WORLD!");
                    stream.Write(bytes, 0, bytes.Length);

                    vfs.AddFile(@"subdir\test.txt", (mode, access) => SparseStream.FromStream(stream, Ownership.None))
                        .Length = stream.Length;

                    vfs.UpdateUsedSpace();
#endif

        vfs.CreateFile += (sender, e) => e.Result = vfs.AddFile(e.Path, (mode, access) => Stream.Null);

        file_system = vfs;

        return file_system;
    }

    private static IFileSystem InitializeFromFsImage(string fsPath)
    {
        if (string.IsNullOrWhiteSpace(fsPath))
        {
            throw new InvalidOperationException($"Missing value for argument: {FsKey}");
        }

        var part_content = File.OpenRead(fsPath);

        if (Path.GetExtension(fsPath).Equals(".iso", StringComparison.OrdinalIgnoreCase))
        {
            return new DiscUtils.Iso9660.CDReader(part_content, joliet: true);
        }
        else
        {
            return FileSystemManager.DetectFileSystems(part_content).FirstOrDefault()?.Open(part_content);
        }
    }

    private static IFileSystem InitializeFromVhd(IDictionary<string, string> arguments, string vhdPath)
    {
        if (string.IsNullOrWhiteSpace(vhdPath))
        {
            throw new InvalidOperationException($"Missing value for argument: {VhdKey}");
        }

        var partNo = 1;

        if (arguments.TryGetValue(PartKey, out var partNoStr) && !int.TryParse(partNoStr, out partNo))
        {
            throw new ArgumentException($"Missing value for argument: {PartKey}");
        }

        var disk = VirtualDisk.OpenDisk(vhdPath, FileAccess.Read) ??
            new DiscUtils.Raw.Disk(vhdPath, FileAccess.Read);

        Console.WriteLine($"Opened image '{vhdPath}', type {disk.DiskTypeInfo.Name}");

        var partitions = disk.Partitions;

        if (partNo > 0 && (partitions == null || partNo > partitions.Count))
        {
            throw new DriveNotFoundException($"Partition {partNo} not found");
        }

        if (partitions == null || partNo == 0 || partitions.Count == 0)
        {
            var disk_content = disk.Content;
            return FileSystemManager.DetectFileSystems(disk_content).FirstOrDefault()?.Open(disk_content);
        }
        else
        {
            Console.WriteLine($"Found partition table, type {partitions.GetType().Name}");

            var part = partitions[partNo - 1];

            Console.WriteLine($"Found partition type {part.TypeAsString}");

            var part_content = part.Open();

            return FileSystemManager.DetectFileSystems(part_content).FirstOrDefault()?.Open(part_content);
        }
    }
}
