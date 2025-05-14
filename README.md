## This fork

This is https://github.com/LTRData/dokan-dotnet

This is a fork of https://github.com/dokan-dev/dokan-dotnet

The main goal of this fork is improved performance by less garbage collector
and heap allocation pressure, at the cost of dropping compatibility with older
runtime versions.

## Important
Modified features in this fork have now been merged into upstream repository and
this fork is no longer maintained. `IDokanOperations` interface from this fork
is now available as `IDokanOperation2` interface in upstream repository:
https://github.com/dokan-dev/dokan-dotnet/blob/master/DokanNet/IDokanOperations2.cs
