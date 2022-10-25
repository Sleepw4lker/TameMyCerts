namespace TameMyCerts.Enums
{
    /// <summary>
    ///     Constants from CertCli.h
    /// </summary>
    internal static class CertCli
    {
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_KEYGEN = 0x200;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;
        public const int CR_IN_FULLRESPONSE = 0x40000;
    }
}