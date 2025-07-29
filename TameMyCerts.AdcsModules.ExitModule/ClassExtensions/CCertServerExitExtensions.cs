// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using CERTCLILib;
using TameMyCerts.AdcsModules.Shared.Enums;
using TameMyCerts.AdcsModules.Shared.Models;

namespace TameMyCerts.AdcsModules.ExitModule.ClassExtensions;

internal static class CCertServerExitExtensions
{
    public static int GetRequestId(this CCertServerExit serverExit)
    {
        return serverExit.GetLongRequestPropertyOrDefault("RequestId");
    }

    public static CertificateDatabaseRow GetDatabaseRow(this CCertServerExit serverExit)
    {
        var notBefore = serverExit.GetDateCertificatePropertyOrDefault("NotBefore");
        var notAfter = serverExit.GetDateCertificatePropertyOrDefault("NotAfter");
        var keyLength = serverExit.GetLongCertificatePropertyOrDefault("PublicKeyLength");
        var publicKey = serverExit.GetBinaryCertificatePropertyOrDefault("RawPublicKey");
        var rawRequest = serverExit.GetBinaryCertificatePropertyOrDefault("RawRequest");
        var requestId = serverExit.GetLongRequestPropertyOrDefault("RequestID");
        var requesterName = serverExit.GetStringRequestPropertyOrDefault("RequesterName");
        var requestType = serverExit.GetLongRequestPropertyOrDefault("RequestType") ^ CertCli.CR_IN_FULLRESPONSE;
        var upn = serverExit.GetStringCertificatePropertyOrDefault("UPN") ?? string.Empty;
        var distinguishedName =
            serverExit.GetStringRequestPropertyOrDefault("Request.DistinguishedName") ?? string.Empty;
        var certificateTemplate = serverExit.GetStringCertificatePropertyOrDefault("CertificateTemplate");
        var requestAttributes = serverExit.GetRequestAttributes();
        var certificateExtensions = serverExit.GetCertificateExtensions();
        var keyAlgorithm =
            GetKeyAlgorithmFamily(serverExit.GetStringCertificatePropertyOrDefault("PublicKeyAlgorithm"));
        var subjectRelativeDistinguishedNames = serverExit.GetSubjectRelativeDistinguishedNames();

        return new CertificateDatabaseRow(
            notBefore, notAfter, keyLength, publicKey, rawRequest, requestId, requesterName, requestType, upn,
            distinguishedName, certificateTemplate, requestAttributes, certificateExtensions, keyAlgorithm,
            subjectRelativeDistinguishedNames);
    }

    private static KeyAlgorithmFamily GetKeyAlgorithmFamily(string oid)
    {
        return oid switch
        {
            WinCrypt.szOID_RSA_RSA => KeyAlgorithmFamily.RSA,
            WinCrypt.szOID_X957_DSA => KeyAlgorithmFamily.DSA,
            WinCrypt.szOID_ECC_PUBLIC_KEY => KeyAlgorithmFamily.ECC,
            _ => KeyAlgorithmFamily.UNKNOWN
        };
    }

    #region GetSubjectDistinguishedName

    public static List<KeyValuePair<string, string>> GetSubjectRelativeDistinguishedNames(
        this CCertServerExit serverExit)
    {
        var result = new List<KeyValuePair<string, string>>();

        foreach (var rdnType in RdnTypes.ToList())
        {
            var value = serverExit.GetStringRequestPropertyOrDefault(RdnTypes.NameProperty[rdnType]);

            if (value == null)
            {
                continue;
            }

            // NewLine qualifies to separate multiple RDNs of same type, regardless if requested RDNs were properly
            // separated or contained newlines
            using (var reader = new StringReader(value))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    result.Add(new KeyValuePair<string, string>(rdnType, line));
                }
            }
        }

        return result;
    }

    #endregion

    #region GetRequestAttributes

    public static Dictionary<string, string> GetRequestAttributes(this CCertServerExit serverExit)
    {
        // Note that it should be safe to use a Dictionary here as request attributes can only appear once in the CA database
        var attributeList = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
        string attributeName;

        serverExit.EnumerateAttributesSetup(0);

        do
        {
            attributeName = serverExit.EnumerateAttributes();
            if (attributeName != null)
            {
                attributeList.Add(attributeName, serverExit.GetRequestAttribute(attributeName));
            }
        } while (attributeName != null);

        serverExit.EnumerateAttributesClose();

        return attributeList;
    }

    #endregion

    #region GetRequestExtensions

    public static Dictionary<string, byte[]> GetCertificateExtensions(this CCertServerExit serverExit)
    {
        var extensionList = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);
        string extensionOid;

        serverExit.EnumerateExtensionsSetup(0);

        do
        {
            extensionOid = serverExit.EnumerateExtensions();
            if (extensionOid != null)
            {
                extensionList.Add(extensionOid, serverExit.GetCertificateExtensionOrDefault(extensionOid));
            }
        } while (extensionOid != null);

        serverExit.EnumerateExtensionsClose();

        return extensionList;
    }

    #endregion


    #region GetCertificateExtension

    public static byte[] GetCertificateExtensionOrDefault(this CCertServerExit serverExit, string name)
    {
        // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
        var variantObjectPtr = Marshal.AllocHGlobal(2048);

        try
        {
            // Get VARIANT containing certificate bytes
            // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
            serverExit.GetCertificateExtension(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
            var bstrPtr = Marshal.ReadIntPtr(variantObjectPtr, 8);
            var bstrLen = Marshal.ReadInt32(bstrPtr, -4);
            var result = new byte[bstrLen];
            Marshal.Copy(bstrPtr, result, 0, bstrLen);

            return result;
        }
        catch
        {
            return default;
        }
        finally
        {
            OleAut32.VariantClear(variantObjectPtr);
            Marshal.FreeHGlobal(variantObjectPtr);
        }
    }

    #endregion


    #region GetCertificateProperty

    private static T GetCertificateProperty<T>(this ICertServerExit serverExit, string name, int type)
    {
        var variantObjectPtr = Marshal.AllocHGlobal(2048);

        try
        {
            serverExit.GetCertificateProperty(name, type, variantObjectPtr);
            var result = (T)Marshal.GetObjectForNativeVariant(variantObjectPtr);
            return result;
        }
        catch
        {
            return default;
        }
        finally
        {
            OleAut32.VariantClear(variantObjectPtr);
            Marshal.FreeHGlobal(variantObjectPtr);
        }
    }

    public static DateTimeOffset GetDateCertificatePropertyOrDefault(this CCertServerExit serverExit,
        string name)
    {
        return new DateTimeOffset(serverExit.GetCertificateProperty<DateTime>(name, CertSrv.PROPTYPE_DATE)
            .ToUniversalTime());
    }

    public static string GetStringCertificatePropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        return serverExit.GetCertificateProperty<string>(name, CertSrv.PROPTYPE_STRING);
    }

    public static int GetLongCertificatePropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        return serverExit.GetCertificateProperty<int>(name, CertSrv.PROPTYPE_LONG);
    }

    public static byte[] GetBinaryCertificatePropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
        var variantObjectPtr = Marshal.AllocHGlobal(2048);

        try
        {
            // Get VARIANT containing certificate bytes
            // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
            serverExit.GetCertificateProperty(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
            var bstrPtr = Marshal.ReadIntPtr(variantObjectPtr, 8);
            var bstrLen = Marshal.ReadInt32(bstrPtr, -4);
            var result = new byte[bstrLen];
            Marshal.Copy(bstrPtr, result, 0, bstrLen);

            return result;
        }
        catch
        {
            return default;
        }
        finally
        {
            OleAut32.VariantClear(variantObjectPtr);
            Marshal.FreeHGlobal(variantObjectPtr);
        }
    }

    #endregion

    #region GetRequestProperty

    private static T GetRequestProperty<T>(this ICertServerExit serverExit, string name, int type)
    {
        var variantObjectPtr = Marshal.AllocHGlobal(2048);

        try
        {
            serverExit.GetRequestProperty(name, type, variantObjectPtr);
            var result = (T)Marshal.GetObjectForNativeVariant(variantObjectPtr);
            return result;
        }
        catch
        {
            return default;
        }
        finally
        {
            OleAut32.VariantClear(variantObjectPtr);
            Marshal.FreeHGlobal(variantObjectPtr);
        }
    }

    public static DateTimeOffset GetDateRequestPropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        return new DateTimeOffset(serverExit.GetRequestProperty<DateTime>(name, CertSrv.PROPTYPE_DATE)
            .ToUniversalTime());
    }

    public static string GetStringRequestPropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        return serverExit.GetRequestProperty<string>(name, CertSrv.PROPTYPE_STRING);
    }

    public static int GetLongRequestPropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        return serverExit.GetRequestProperty<int>(name, CertSrv.PROPTYPE_LONG);
    }

    public static byte[] GetBinaryRequestPropertyOrDefault(this CCertServerExit serverExit, string name)
    {
        // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
        var variantObjectPtr = Marshal.AllocHGlobal(2048);

        try
        {
            // Get VARIANT containing certificate bytes
            // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
            serverExit.GetRequestProperty(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
            var bstrPtr = Marshal.ReadIntPtr(variantObjectPtr, 8);
            var bstrLen = Marshal.ReadInt32(bstrPtr, -4);
            var result = new byte[bstrLen];
            Marshal.Copy(bstrPtr, result, 0, bstrLen);
            return result;
        }
        catch
        {
            return default;
        }
        finally
        {
            OleAut32.VariantClear(variantObjectPtr);
            Marshal.FreeHGlobal(variantObjectPtr);
        }
    }

    #endregion
}