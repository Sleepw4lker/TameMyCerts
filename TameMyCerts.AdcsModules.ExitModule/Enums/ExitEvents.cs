namespace TameMyCerts.AdcsModules.ExitModule.Enums;

internal enum ExitEvents
{
    Invalid = 0x0,
    CertIssued = 0x1,
    CertPending = 0x2,
    CertDenied = 0x4,
    CertRevoked = 0x8,
    CertRetrievePending = 0x10,
    CRLIssued = 0x20,
    Shutdown = 0x40
}