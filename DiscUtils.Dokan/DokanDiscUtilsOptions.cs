using System;

namespace DiscUtils.Dokan
{
    [Flags]
    public enum DokanDiscUtilsOptions
    {
        None            = 0x00,
        ForceReadOnly   = 0x01,
        AcessCheck  = 0x02,
        HiddenAsNormal  = 0x04,
        LeaveFsOpen     = 0x08,
        BlockExecute    = 0x10
    }
}