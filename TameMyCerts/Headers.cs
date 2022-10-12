namespace TameMyCerts
{
    /// <summary>
    ///     Constants from CertCli.h
    /// </summary>
    public static class CertCli
    {
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_KEYGEN = 0x200;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;
        public const int CR_IN_FULLRESPONSE = 0x40000;
    }

    /// <summary>
    ///     Constants from CertSrv.h
    /// </summary>
    public static class CertSrv
    {
        public const int VR_PENDING = 0;
        public const int VR_INSTANT_OK = 1;
        public const int VR_INSTANT_BAD = 2;

        public const int CERTLOG_MINIMAL = 0;
        public const int CERTLOG_TERSE = 1;
        public const int CERTLOG_ERROR = 2;
        public const int CERTLOG_WARNING = 3;
        public const int CERTLOG_VERBOSE = 4;
        public const int CERTLOG_EXHAUSTIVE = 5;

        public const int PROPTYPE_LONG = 1;
        public const int PROPTYPE_DATE = 2;
        public const int PROPTYPE_BINARY = 3;
        public const int PROPTYPE_STRING = 4;
        public const int PROPTYPE_ANSI = 5;

        public const int ENUM_ENTERPRISE_ROOTCA = 0;
        public const int ENUM_ENTERPRISE_SUBCA = 1;
        public const int ENUM_STANDALONE_ROOTCA = 3;
        public const int ENUM_STANDALONE_SUBCA = 4;

        public const int EDITF_ATTRIBUTEENDDATE = 0x00000020;
        public const int EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000;
    }

    /// <summary>
    ///     Constants from CertCa.h
    /// </summary>
    public static class CertCa
    {
        /// <summary>
        ///     The enrolling application must supply the subject name.
        /// </summary>
        public const int CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1;

        /// <summary>
        ///     This is a machine cert type
        /// </summary>
        public const int CT_FLAG_MACHINE_TYPE = 0x40;
    }

    /// <summary>
    ///     Constants from WinCrypt.h
    /// </summary>
    public static class WinCrypt
    {
        public const string szOID_RSA_RSA = "1.2.840.113549.1.1.1";
        public const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";
        public const string szOID_OS_VERSION = "1.3.6.1.4.1.311.13.2.3";
        public const string szOID_ENROLLMENT_CSP_PROVIDER = "1.3.6.1.4.1.311.13.2.2";
        public const string szOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20";
        public const string szOID_DS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2";
        public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";
    }

    /// <summary>
    ///     Constants from WinError.h
    /// </summary>
    public static class WinError
    {
        /// <summary>
        ///     The operation completed successfully.
        /// </summary>
        public const int ERROR_SUCCESS = 0;

        /// <summary>
        ///     The specified time is invalid.
        /// </summary>
        public const int ERROR_INVALID_TIME = 1901;

        /// <summary>
        ///     An internal error occurred.
        /// </summary>
        public const int NTE_FAIL = unchecked((int) 0x80090020);

        /// <summary>
        ///     The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
        /// </summary>
        public const int CERTSRV_E_TEMPLATE_DENIED = unchecked((int) 0x80094012);

        /// <summary>
        ///     The request subject name is invalid or too long.
        /// </summary>
        public const int CERTSRV_E_BAD_REQUESTSUBJECT = unchecked((int) 0x80094001);

        /// <summary>
        ///     The requested certificate template is not supported by this CA.
        /// </summary>
        public const int CERTSRV_E_UNSUPPORTED_CERT_TYPE = unchecked((int) 0x80094800);

        /// <summary>
        ///     The public key does not meet the minimum size required by the specified certificate template.
        /// </summary>
        public const int CERTSRV_E_KEY_LENGTH = unchecked((int) 0x80094811);

        /// <summary>
        ///     The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded.
        /// </summary>
        public const int CERT_E_INVALID_NAME = unchecked((int) 0x800B0114);
    }

    /// <summary>
    ///     Active Directory user account control flags
    /// </summary>
    public static class UserAccountControl
    {
        /// <summary>
        ///     The user account is disabled.
        /// </summary>
        public const int ACCOUNTDISABLE = 0x00000002;
    }
}