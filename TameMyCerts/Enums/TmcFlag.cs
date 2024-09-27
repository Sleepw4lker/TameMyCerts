using System;

namespace TameMyCerts.Enums
{
    [Flags]
    public enum TmcFlag : uint
    {
        TMC_DENY_IF_NO_POLICY = 0x1,
        TMC_WARN_ONLY_ON_INSECURE_FLAGS = 0x2,
        TMC_DEEP_LDAP_SEARCH = 0x4
    }
}