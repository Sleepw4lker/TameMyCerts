using System;

namespace TameMyCerts.Enums;

[Flags]
public enum TmcFlag : uint
{
    TMC_DENY_IF_NO_POLICY = 0x1,
    TMC_WARN_ONLY_ON_INSECURE_FLAGS = 0x2,
    TMC_RESOLVE_NESTED_GROUP_MEMBERSHIPS = 0x4
}