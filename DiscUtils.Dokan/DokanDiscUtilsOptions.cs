using System;
using System.Diagnostics.CodeAnalysis;

namespace DiscUtils.Dokan
{
    [Flags, SuppressMessage("Design", "CA1704")]
    public enum DokanDiscUtilsOptions
    {
        None            = 0x00,
        ForceReadOnly   = 0x01,
        AcessCheck      = 0x02,
        HiddenAsNormal  = 0x04,
        LeaveFSOpen     = 0x08,
        BlockExecute    = 0x10
    }
}

