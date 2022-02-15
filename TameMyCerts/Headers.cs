// Some constants that are defined in Windows SDK header files

namespace TameMyCerts
{
    // Constants from CertCli.h
    public static class CertCli
    {
        // See also https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_KEYGEN = 0x200;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;
        public const int CR_IN_FULLRESPONSE = 0x40000;
    }

    // Constants from CertSrv.h
    public static class CertSrv
    {
        // See also https://docs.microsoft.com/en-us/windows/win32/api/certpol/nf-certpol-icertpolicy-verifyrequest
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
    }

    // Constants from CertCa.h
    public static class CertCa
    {
        // The enrolling application must supply the subject name.
        public const int CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1;
    }

    // Constants from WinError.h
    public static class WinError
    {
        // The operation completed successfully.
        public const int ERROR_SUCCESS = 0;

        //  An internal error occurred.
        public const int NTE_FAIL = unchecked((int) 0x80090020);

        // The request subject name is invalid or too long.
        public const int CERTSRV_E_BAD_REQUESTSUBJECT = unchecked((int) 0x80094001);

        // The requested certificate template is not supported by this CA.
        public const int CERTSRV_E_UNSUPPORTED_CERT_TYPE = unchecked((int) 0x80094800);

        // The public key does not meet the minimum size required by the specified certificate template.
        public const int CERTSRV_E_KEY_LENGTH = unchecked((int) 0x80094811);

        // The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded.
        public const int CERT_E_INVALID_NAME = unchecked((int) 0x800B0114);
    }
}