using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum PatternType
{
    [XmlEnum(Name = "RegExIgnoreCase")]
    REGEX_IGNORE_CASE,

    [XmlEnum(Name = "RegEx")]
    REGEX,

    [XmlEnum(Name = "Cidr")]
    CIDR,

    [XmlEnum(Name = "ExactMatchIgnoreCase")]
    EXACT_MATCH_IGNORE_CASE,

    [XmlEnum(Name = "ExactMatch")]
    EXACT_MATCH
}