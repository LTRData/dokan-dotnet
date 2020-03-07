using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using DiscUtils;
using DiscUtils.Dokan;
using DiscUtils.Streams;
using DiscUtils.VirtualFileSystem;
using DokanNet;

namespace DiscUtilsFs
{
    internal class Program
    {
        private const string VhdKey = "-vhd";
        private const string PartKey = "-part";
        private const string FsKey = "-fs";
        private const string MountKey = "-where";

        private static void Main(string[] args)
        {
            try
            {
                var asms = new[]
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
                    typeof(DiscUtils.Xfs.XfsFileSystem).Assembly
                };
                
                foreach (var asm in asms.Distinct())
                {
                    DiscUtils.Setup.SetupHelper.RegisterAssembly(asm);
                }

                var arguments = args
                   .Select(x => x.Split(new char[] { '=' }, 2, StringSplitOptions.RemoveEmptyEntries))
                   .ToDictionary(x => x[0], x => x.Length > 1 ? x[1] : null, StringComparer.OrdinalIgnoreCase);

                if (!(arguments.TryGetValue(MountKey, out var mountPathObj) && mountPathObj is string mountPath))
                   mountPath = @"N:\";

                IFileSystem file_system;

                if (arguments.TryGetValue(VhdKey, out var vhdPath))
                {
                    if (string.IsNullOrWhiteSpace(vhdPath))
                        throw new ArgumentException("Missing value for argument", VhdKey);

                    var partNo = 1;

                    if (arguments.TryGetValue(PartKey, out var partNoStr) && !int.TryParse(partNoStr, out partNo))
                        throw new ArgumentException("Missing value for argument", PartKey);

                    var disk = VirtualDisk.OpenDisk(vhdPath, System.IO.FileAccess.Read) ??
                        new DiscUtils.Raw.Disk(vhdPath, System.IO.FileAccess.Read);

                    Console.WriteLine($"Opened image '{vhdPath}', type {disk.DiskTypeInfo.Name}");

                    var partitions = disk.Partitions;

                    if (partNo > 0 && (partitions == null || partNo > partitions.Count))
                    {
                        throw new DriveNotFoundException($"Partition {partNo} not found");
                    }

                    if (partitions == null || partNo == 0 || partitions.Count == 0)
                    {
                        var disk_content = disk.Content;
                        file_system = FileSystemManager.DetectFileSystems(disk_content).FirstOrDefault()?.Open(disk_content);
                    }
                    else
                    {
                        Console.WriteLine($"Found partition table, type {partitions.GetType().Name}");

                        var part = partitions[partNo - 1];

                        Console.WriteLine($"Found partition type {part.TypeAsString}");

                        var part_content = part.Open();

                        file_system = FileSystemManager.DetectFileSystems(part_content).FirstOrDefault()?.Open(part_content);
                    }
                }
                else if (arguments.TryGetValue(FsKey, out var fsPath))
                {
                    if (string.IsNullOrWhiteSpace(fsPath))
                        throw new ArgumentException("Missing value for argument", FsKey);

                    var part_content = File.OpenRead(fsPath);

                    if (Path.GetExtension(fsPath).Equals(".iso", StringComparison.OrdinalIgnoreCase))
                    {
                        file_system = new DiscUtils.Iso9660.CDReader(part_content, joliet: true);
                    }
                    else
                    {
                        file_system = FileSystemManager.DetectFileSystems(part_content).FirstOrDefault()?.Open(part_content);
                    }
                }
                else
                {
                    var vfs = new VirtualFileSystem(new VirtualFileSystemOptions
                    {
                        HasSecurity = false,
                        IsThreadSafe = false,
                        VolumeLabel = "VirtualFs"
                    });

                    var stream = new MemoryStream();
                    var bytes = Encoding.ASCII.GetBytes("HELLO WORLD!");
                    stream.Write(bytes, 0, bytes.Length);

                    vfs.AddFile(@"subdir\test.txt", (mode, access) => SparseStream.FromStream(stream, Ownership.None))
                        .Length = stream.Length;

                    vfs.UpdateUsedSpace();

                    vfs.CreateFile += (sender, e) => e.Result = vfs.AddFile(e.Path, (mode, access) => Stream.Null);

                    file_system = vfs;
                }

                if (file_system == null)
                {
                    Console.WriteLine($"No supported file system found.");
                    return;
                }

                Console.WriteLine($"Found file system, type {file_system.GetType().Name}");

                if (file_system is DiscUtils.Ntfs.NtfsFileSystem ntfs)
                {
                    ntfs.NtfsOptions.HideHiddenFiles = false;
                    ntfs.NtfsOptions.HideMetafiles = false;
                    ntfs.NtfsOptions.HideSystemFiles = false;
                }

                var discutils_options = DokanDiscUtilsOptions.BlockExecute |
                    DokanDiscUtilsOptions.HiddenAsNormal;

                var dokan_discutils = new DokanDiscUtils(file_system, discutils_options);

                var mountOptions = DokanOptions.OptimizeSingleNameSearch;

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

                using (var service = new DokanService(dokan_discutils, mountPath, mountOptions))
                {
                    service.Start();

                    while (service.Running && !new DriveInfo(mountPath).IsReady)
                    {
                        Thread.Sleep(200);
                    }

                    if (service.Running)
                    {
                        Process.Start(mountPath);

                        Console.WriteLine("Success. Press Escape to dismount.");

                        while (Console.ReadKey().Key != ConsoleKey.Escape)
                        {
                        }

                        Console.WriteLine();

                        Console.WriteLine("Dismounting...");
                    }
                    else
                    {
                        Console.WriteLine("Failed to mount.");
                    }
                }

                Console.WriteLine("Success.");
            }
            catch (DokanException ex)
            {
                Console.WriteLine($@"Error: {ex.Message}");
            }
        }
    }
}