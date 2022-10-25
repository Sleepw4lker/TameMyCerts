namespace TameMyCerts.Enums
{
    /// <summary>
    ///     Certification authority types from CertSrv.h
    /// </summary>
    public enum CaType
    {
        ENUM_ENTERPRISE_ROOTCA = 0,
        ENUM_ENTERPRISE_SUBCA = 1,
        ENUM_STANDALONE_ROOTCA = 3,
        ENUM_STANDALONE_SUBCA = 4
    }
}