using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum YubikeyPinPolicy
{
    [XmlEnum(Name = "None")]
    NONE = 0,

    [XmlEnum(Name = "Never")]
    NEVER = 1,

    [XmlEnum(Name = "Once")]
    ONCE = 2,

    [XmlEnum(Name = "Always")]
    ALWAYS = 3,

    [XmlEnum(Name = "MatchOnce")]
    MATCH_ONCE = 4,

    [XmlEnum(Name = "MatchAlways")]
    MATCH_ALWAYS = 5,

    [XmlEnum(Name = "Default")]
    DEFAULT = 32
}