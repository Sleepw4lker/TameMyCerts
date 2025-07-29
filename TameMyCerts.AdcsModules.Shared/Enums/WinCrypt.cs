namespace TameMyCerts.AdcsModules.Shared.Enums;

/// <summary>
///     Well-known OIDs from WinCrypt.h and related sources.
/// </summary>
public static class WinCrypt
{
    /// <summary>
    /// RSA encryption OID (PKCS #1).
    /// </summary>
    public const string szOID_RSA_RSA = "1.2.840.113549.1.1.1";

    /// <summary>
    /// DSA encryption OID (X9.57).
    /// </summary>
    public const string szOID_X957_DSA = "1.2.840.10040.4.1";

    /// <summary>
    /// ECC public key OID.
    /// </summary>
    public const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";

    /// <summary>
    /// Microsoft request client info extension OID.
    /// </summary>
    public const string szOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20";

    /// <summary>
    /// Microsoft NTDS object SID extension OID.
    /// </summary>
    public const string szOID_NTDS_OBJECTSID = "1.3.6.1.4.1.311.25.2.1";

    /// <summary>
    /// Microsoft NTDS CA security extension OID.
    /// </summary>
    public const string szOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2";

    /// <summary>
    /// Subject Alternative Name 2 extension OID.
    /// </summary>
    public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";

    /// <summary>
    /// CRL Distribution Points extension OID.
    /// </summary>
    public const string szOID_CRL_DIST_POINTS = "2.5.29.31";

    /// <summary>
    /// Authority Information Access extension OID.
    /// </summary>
    public const string szOID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";

    /// <summary>
    /// PKIX OCSP responder OID.
    /// </summary>
    public const string szOID_PKIX_OCSP = "1.3.6.1.5.5.7.48.1";

    /// <summary>
    /// PKIX CA Issuers OID.
    /// </summary>
    public const string szOID_PKIX_CA_ISSUERS = "1.3.6.1.5.5.7.48.2";
}