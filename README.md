## This fork

This is a fork of https://github.com/dokan-dev/dokan-dotnet

The main goal of this fork is improved performance by less garbage collector
and heap allocation pressure, at the cost of dropping compatibility with older
runtime versions.

# Dokan.NET Binding
[![Build status](https://ci.appveyor.com/api/projects/status/w707j7xlu21jf3qa?svg=true)](https://ci.appveyor.com/project/Liryna/dokan-dotnet)
[![NuGet downloads](https://img.shields.io/nuget/dt/DokanNet.svg)](https://www.nuget.org/packages/DokanNet)
[![Version](https://img.shields.io/nuget/v/DokanNet.svg)](https://www.nuget.org/packages/DokanNet)

## What is Dokan.NET Binding
By using Dokan library, you can create your own file systems very easily
without writing device driver. Dokan.NET Binding is a library that allows
you to make a file system on .NET environment.

## Licensing
Dokan.NET Binding is distributed under a version of the "MIT License",
which is a BSD-like license. See the 'license.mit.txt' file for details.

## Environment
.NET Framework 4.6 and 4.8, .NET Standard 2.0 or 2.1 or .NET 6.0.

## How to write a file system
To make a file system, an application needs to implement IDokanOperations interface.
Once implemented, you can invoke Mount function on your driver instance
to mount a drive. The function blocks until the file system is unmounted.
Semantics and parameters are just like Dokan library. Details are described
at 'README.md' file in Dokan library. See sample codes under 'sample'
directory. Administrator privileges are required to run file system
applications.
Doxygen documentation is also available [here](https://dokan-dev.github.io/dokan-dotnet-doc/html/).

## Unmounting
Just run the bellow command or your file system application call Dokan.Unmount
to unmount a drive.

   > dokanctl.exe /u DriveLetter

