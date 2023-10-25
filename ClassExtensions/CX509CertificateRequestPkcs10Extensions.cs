// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.Runtime.InteropServices;
using CERTENROLLLib;
using TameMyCerts.Enums;

namespace TameMyCerts.ClassExtensions
{
    internal static class CX509CertificateRequestPkcs10Extensions
    {
        public static Dictionary<string, byte[]> GetRequestExtensions(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            var extensionList = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

            for (var i = 0; i < certificateRequestPkcs10.X509Extensions.Count; i++)
            {
                extensionList.Add(certificateRequestPkcs10.X509Extensions[i].ObjectId.Value,
                    Convert.FromBase64String(certificateRequestPkcs10.X509Extensions[i]
                        .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)));
            }

            return extensionList;
        }

        public static bool TryInitializeFromInnerRequest(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
            string certificateRequest, int requestType)
        {
            switch (requestType)
            {
                case CertCli.CR_IN_CMC:

                    var certificateRequestCmc =
                        (IX509CertificateRequestCmc)Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certificateRequestCmc.InitializeDecode(certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

                        var innerRequest = certificateRequestCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestCmc);
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    var certificateRequestPkcs7 =
                        (IX509CertificateRequestPkcs7)Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certificateRequestPkcs7.InitializeDecode(certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

                        var innerRequest = certificateRequestPkcs7.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                        certificateRequest = innerRequest.get_RawData();
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certificateRequestPkcs7);
                    }

                    break;
            }

            try
            {
                certificateRequestPkcs10.InitializeDecode(certificateRequest, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static KeyAlgorithmFamily GetKeyAlgorithm(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            switch (certificateRequestPkcs10.PublicKey.Algorithm.Value)
            {
                case WinCrypt.szOID_ECC_PUBLIC_KEY: return KeyAlgorithmFamily.ECC;
                case WinCrypt.szOID_RSA_RSA: return KeyAlgorithmFamily.RSA;
                case WinCrypt.szOID_X957_DSA: return KeyAlgorithmFamily.DSA;
                default: return KeyAlgorithmFamily.UNKNOWN;
            }
        }
        
        public static Dictionary<string, string> GetInlineRequestAttributeList(
            this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            Dictionary<string, string> attributeList = new Dictionary<string, string>();

            for (var i = 0; i < certificateRequestPkcs10.CryptAttributes.Count; i++)
            {
                var cryptAttribute = certificateRequestPkcs10.CryptAttributes[i];

                // Note that there is no need to extract the RequestCSPProvider here as it is automatically added to the extensions table
                if (cryptAttribute.ObjectId.Value != WinCrypt.szOID_REQUEST_CLIENT_INFO)
                {
                    continue;
                }

                string rawData;

                try
                {
                    rawData = cryptAttribute.Values[0].get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64);
                }
                catch
                {
                    continue;
                }

                var clientId = new CX509AttributeClientId();

                try
                {
                    clientId.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);

                    attributeList.Add("ProcessName", clientId.ProcessName.ToLowerInvariant());
                    attributeList.Add("MachineDnsName", clientId.MachineDnsName);
                }
                finally
                {
                    Marshal.ReleaseComObject(clientId);
                }
            }

            return attributeList;
        }

        public static string GetSubjectDistinguishedName(this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
        {
            try
            {
                return certificateRequestPkcs10.Subject.Name;
            }
            catch
            {
                // Subject DN is empty
                return string.Empty;
            }
        }
    }
}