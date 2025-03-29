using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum PolicyAction
{
    [XmlEnum(Name = "Allow")]
    ALLOW,

    [XmlEnum(Name = "Deny")]
    DENY,

    [XmlEnum(Name = "Add")]
    ADD_TO_ISSUED_CERTIFICATE,

    [XmlEnum(Name = "Remove")]
    REMOVE_FROM_ISSUED_CERTIFICATE
}