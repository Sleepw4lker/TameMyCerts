namespace TameMyCerts.Enums
{
    /// <summary>
    ///     Constants from CertSrv.h
    /// </summary>
    internal static class CertSrv
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

        public const int EXTENSION_CRITICAL_FLAG = 0x00000001;
        public const int EXTENSION_DISABLE_FLAG = 0x00000002;
        public const int EXTENSION_DELETE_FLAG = 0x00000004;
    }
}