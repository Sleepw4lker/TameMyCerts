using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum DsMappingPolicyAction
{
    /// <summary>
    ///     The certificate request is allowed to be issued only if a mapped object was found.
    /// </summary>
    [XmlEnum(Name = "Allow")] ALLOW,

    /// <summary>
    ///     The certificate request is denied if a mapped object was found.
    /// </summary>
    [XmlEnum(Name = "Deny")] DENY,

    /// <summary>
    ///     The certificate request is allowed to be issued regardless if a mapped object was found or not.
    /// </summary>
    [XmlEnum(Name = "Continue")] CONTINUE
}