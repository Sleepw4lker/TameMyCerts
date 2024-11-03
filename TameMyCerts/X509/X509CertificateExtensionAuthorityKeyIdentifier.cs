namespace TameMyCerts.X509;

public class X509CertificateExtensionAuthorityKeyIdentifier : X509CertificateExtension
{
    public X509CertificateExtensionAuthorityKeyIdentifier(byte[] authorityKeyIdentifer)
    {
        var result = Asn1BuildNode(0x80, authorityKeyIdentifer);
        result = Asn1BuildNode(0x30, result);
        RawData = result;
    }
}