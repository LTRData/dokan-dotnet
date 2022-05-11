using System;
using System.IO;
using DokanNet;

#pragma warning disable IDE0079 // Remove unnecessary suppression
#pragma warning disable IDE0057 // Use range operator

namespace DokanNetMirror;

internal class Notify
{
    private string sourcePath;
    private string targetPath;
    private DokanInstance dokanCurrentInstance;
    private FileSystemWatcher commonFsWatcher;
    private FileSystemWatcher fileFsWatcher;
    private FileSystemWatcher dirFsWatcher;

    public void Start(string mirrorPath, string mountPath, DokanInstance dokanInstance)
    {
        sourcePath = mirrorPath;
        targetPath = mountPath;
        dokanCurrentInstance = dokanInstance;

        commonFsWatcher = new FileSystemWatcher(mirrorPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.Attributes |
                NotifyFilters.CreationTime |
                NotifyFilters.DirectoryName |
                NotifyFilters.FileName |
                NotifyFilters.LastAccess |
                NotifyFilters.LastWrite |
                NotifyFilters.Security |
                NotifyFilters.Size
        };

        commonFsWatcher.Changed += OnCommonFileSystemWatcherChanged;
        commonFsWatcher.Created += OnCommonFileSystemWatcherCreated;
        commonFsWatcher.Renamed += OnCommonFileSystemWatcherRenamed;

        commonFsWatcher.EnableRaisingEvents = true;

        fileFsWatcher = new FileSystemWatcher(mirrorPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName
        };

        fileFsWatcher.Deleted += OnCommonFileSystemWatcherFileDeleted;

        fileFsWatcher.EnableRaisingEvents = true;

        dirFsWatcher = new FileSystemWatcher(mirrorPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.DirectoryName
        };

        dirFsWatcher.Deleted += OnCommonFileSystemWatcherDirectoryDeleted;

        dirFsWatcher.EnableRaisingEvents = true;
    }

    private string AlterPathToMountPath(string path)
    {
        var relativeMirrorPath = path.AsSpan(sourcePath.Length).TrimStart('\\').ToString();

        return Path.Combine(targetPath, relativeMirrorPath);
    }

    private void OnCommonFileSystemWatcherFileDeleted(object sender, FileSystemEventArgs e)
    {
        if (dokanCurrentInstance.IsDisposing)
        {
            return;
        }

        var fullPath = AlterPathToMountPath(e.FullPath);

        Dokan.Notify.Delete(dokanCurrentInstance, fullPath, false);
    }

    private void OnCommonFileSystemWatcherDirectoryDeleted(object sender, FileSystemEventArgs e)
    {
        if (dokanCurrentInstance.IsDisposing)
        {
            return;
        }

        var fullPath = AlterPathToMountPath(e.FullPath);

        Dokan.Notify.Delete(dokanCurrentInstance, fullPath, true);
    }

    private void OnCommonFileSystemWatcherChanged(object sender, FileSystemEventArgs e)
    {
        if (dokanCurrentInstance.IsDisposing)
        {
            return;
        }

        var fullPath = AlterPathToMountPath(e.FullPath);

        Dokan.Notify.Update(dokanCurrentInstance, fullPath);
    }

    private void OnCommonFileSystemWatcherCreated(object sender, FileSystemEventArgs e)
    {
        if (dokanCurrentInstance.IsDisposing)
        {
            return;
        }

        var fullPath = AlterPathToMountPath(e.FullPath);
        var isDirectory = Directory.Exists(fullPath);

        Dokan.Notify.Create(dokanCurrentInstance, fullPath, isDirectory);
    }

    private void OnCommonFileSystemWatcherRenamed(object sender, RenamedEventArgs e)
    {
        if (dokanCurrentInstance.IsDisposing)
        {
            return;
        }

        var oldFullPath = AlterPathToMountPath(e.OldFullPath);
        var oldDirectoryName = Path.GetDirectoryName(e.OldFullPath);

        var fullPath = AlterPathToMountPath(e.FullPath);
        var directoryName = Path.GetDirectoryName(e.FullPath);

        var isDirectory = Directory.Exists(e.FullPath);
        var isInSameDirectory = oldDirectoryName.Equals(directoryName);

        Dokan.Notify.Rename(dokanCurrentInstance, oldFullPath, fullPath, isDirectory, isInSameDirectory);
    }
}
