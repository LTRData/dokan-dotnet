using System;
using System.Linq;
using DokanNet;

namespace DokanNetMirror;

internal class Program
{
    private const string MirrorKey = "-what";
    private const string MountKey = "-where";

    private static int Main(string[] args)
    {
        try
        {
            var arguments = args
               .Select(x => x.Split(new char[] { '=' }, 2, StringSplitOptions.RemoveEmptyEntries))
               .ToDictionary(x => x[0], x => x.Length > 1 ? x[1] as object : true, StringComparer.OrdinalIgnoreCase);

            var mirrorPath = arguments.ContainsKey(MirrorKey)
               ? arguments[MirrorKey] as string
               : @"C:\";

            var mountPath = arguments.ContainsKey(MountKey)
               ? arguments[MountKey] as string
               : @"N:\";

            var mirror = new Mirror(mirrorPath);

            Dokan.Init();

            using (var dokanInstance = mirror.CreateFileSystem(mountPath, DokanOptions.DebugMode | DokanOptions.EnableNotificationAPI))
            {
                var notify = new Notify();
                notify.Start(mirrorPath, mountPath, dokanInstance);
                dokanInstance.WaitForFileSystemClosed(uint.MaxValue);
            }

            Dokan.Shutdown();

            Console.WriteLine("Success");

            return 0;
        }
        catch (DokanException ex)
        {
            Console.WriteLine($"Error: {ex.Message}");

            return ex.HResult;
        }
    }
}
