using System.Xml.Serialization;

namespace TameMyCerts.AdcsModules.PolicyModule.Enums;

public enum YubikeyEdition
{
    [XmlEnum(Name = "Normal")]
    NORMAL,

    [XmlEnum(Name = "FIPS")]
    FIPS,

    [XmlEnum(Name = "CSPN")]
    CSPN
}