using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum YubikeyTouchPolicy
{
    [XmlEnum(Name = "None")]
    NONE = 0,

    [XmlEnum(Name = "Never")]
    NEVER = 1,

    [XmlEnum(Name = "Always")]
    ALWAYS = 2,

    [XmlEnum(Name = "Cached")]
    CACHED = 3,

    [XmlEnum(Name = "Default")]
    DEFAULT = 32
}