// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.Linq;
using System.Runtime.InteropServices;
using CERTCLILib;
using TameMyCerts.Enums;

namespace TameMyCerts.ClassExtensions
{
    internal static class CCertServerPolicyExtensions
    {
        #region GetSubjectDistinguishedName

        public static List<KeyValuePair<string, string>> GetSubjectRelativeDistinguishedNames(
            this CCertServerPolicy serverPolicy)
        {
            var rdnInfo =
                new Dictionary<string, string>
                {
                    {"emailAddress", "Subject.Email"},
                    {"commonName", "Subject.CommonName"},
                    {"organizationName", "Subject.Organization"},
                    {"organizationalUnitName", "Subject.OrgUnit"},
                    {"localityName", "Subject.Locality"},
                    {"stateOrProvinceName", "Subject.State"},
                    {"countryName", "Subject.Country"},
                    {"title", "Subject.Title"},
                    {"givenName", "Subject.GivenName"},
                    {"initials", "Subject.Initials"},
                    {"surname", "Subject.SurName"},
                    {"streetAddress", "Subject.StreetAddress"},
                    {"unstructuredName", "Subject.UnstructuredName"},
                    {"unstructuredAddress", "Subject.UnstructuredAddress"},
                    {"serialNumber", "Subject.DeviceSerialNumber"}
                };

            return (from keyValuePair in rdnInfo
                let value = serverPolicy.GetStringRequestPropertyOrDefault(keyValuePair.Value)
                where value != null
                select new KeyValuePair<string, string>(keyValuePair.Key, value)).ToList();
        }

        #endregion

        #region GetRequestAttributes

        public static Dictionary<string, string> GetRequestAttributes(this CCertServerPolicy serverPolicy)
        {
            // Note that it should be safe to use a Dictionary here as request attributes can only appear once in the CA database
            var attributeList = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
            string attributeName;

            serverPolicy.EnumerateAttributesSetup(0);

            do
            {
                attributeName = serverPolicy.EnumerateAttributes();
                if (attributeName != null)
                {
                    attributeList.Add(attributeName, serverPolicy.GetRequestAttribute(attributeName));
                }
            } while (attributeName != null);

            serverPolicy.EnumerateAttributesClose();

            return attributeList;
        }

        #endregion

        #region GetRequestExtensions

        public static Dictionary<string, string> GetCertificateExtensions(this CCertServerPolicy serverPolicy)
        {
            var extensionList = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
            string extensionOid;

            serverPolicy.EnumerateExtensionsSetup(0);

            do
            {
                extensionOid = serverPolicy.EnumerateExtensions();
                if (extensionOid != null)
                {
                    extensionList.Add(extensionOid,
                        Convert.ToBase64String(serverPolicy.GetCertificateExtensionOrDefault(extensionOid)));
                }
            } while (extensionOid != null);

            serverPolicy.EnumerateExtensionsClose();

            return extensionList;
        }

        #endregion

        #region SetCertificateExtension

        public static void SetCertificateExtension(this CCertServerPolicy serverPolicy, string oid, string value,
            bool critical = false)
        {
            // Kudos to Vadims Podans for his research and support!

            var rawData = Convert.FromBase64String(value);

            var pBstr = Marshal.AllocHGlobal(rawData.Length + 4);
            Marshal.WriteInt32(pBstr, 0, rawData.Length);
            Marshal.Copy(rawData, 0, pBstr + 4, rawData.Length);

            var variant = new OleAut32.VARIANT
            {
                vt = 8, // VT_BSTR
                pvRecord = pBstr + 4
            };

            var pvarValue = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OleAut32.VARIANT)));
            Marshal.StructureToPtr(variant, pvarValue, false);
            var dwCritical = critical ? CertSrv.EXTENSION_CRITICAL_FLAG : 0;

            try
            {
                serverPolicy.SetCertificateExtension(oid, CertSrv.PROPTYPE_BINARY, dwCritical, pvarValue);
            }
            finally
            {
                Marshal.FreeHGlobal(pBstr);
                Marshal.FreeHGlobal(pvarValue);
            }
        }

        #endregion

        #region DisableCertificateExtension

        public static void DisableCertificateExtension(this CCertServerPolicy serverPolicy, string oid)
        {
            // Kudos to Vadims Podans for his research and support!

            var variant = new OleAut32.VARIANT
            {
                vt = 0, // VT_EMPTY
                pvRecord = IntPtr.Zero
            };

            var pvarValue = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OleAut32.VARIANT)));
            Marshal.StructureToPtr(variant, pvarValue, false);

            try
            {
                serverPolicy.SetCertificateExtension(oid, CertSrv.PROPTYPE_BINARY, CertSrv.EXTENSION_DISABLE_FLAG,
                    pvarValue);
            }
            finally
            {
                Marshal.FreeHGlobal(pvarValue);
            }
        }

        #endregion

        #region DisableCertificateProperty

        public static void DisableCertificateProperty(this CCertServerPolicy serverPolicy, string name)
        {
            serverPolicy.SetCertificateProperty(name, CertSrv.PROPTYPE_STRING, null);
        }

        #endregion

        #region GetCertificateExtension

        public static byte[] GetCertificateExtensionOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
            var variantObjectPtr = Marshal.AllocHGlobal(2048);

            try
            {
                // Get VARIANT containing certificate bytes
                // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
                serverPolicy.GetCertificateExtension(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
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

        #region SetCertificateProperty

        public static void SetCertificateProperty(this CCertServerPolicy serverPolicy, string name,
            DateTimeOffset value)
        {
            serverPolicy.SetCertificateProperty(name, value.UtcDateTime);
        }

        public static void SetCertificateProperty(this CCertServerPolicy serverPolicy, string name, DateTime value)
        {
            // raises an exception when trying to set to the same value
            if (value == serverPolicy.GetDateCertificatePropertyOrDefault(name).UtcDateTime)
            {
                return;
            }

            serverPolicy.SetCertificateProperty(name, CertSrv.PROPTYPE_DATE, value);
        }

        public static void SetCertificateProperty(this CCertServerPolicy serverPolicy, string name, string value)
        {
            serverPolicy.SetCertificateProperty(name, CertSrv.PROPTYPE_STRING, value);
        }

        #endregion

        #region GetCertificateProperty

        private static T GetCertificateProperty<T>(this ICertServerPolicy serverPolicy, string name, int type)
        {
            var variantObjectPtr = Marshal.AllocHGlobal(2048);

            try
            {
                serverPolicy.GetCertificateProperty(name, type, variantObjectPtr);
                var result = (T) Marshal.GetObjectForNativeVariant(variantObjectPtr);
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

        public static DateTimeOffset GetDateCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy,
            string name)
        {
            return new DateTimeOffset(serverPolicy.GetCertificateProperty<DateTime>(name, CertSrv.PROPTYPE_DATE)
                .ToUniversalTime());
        }

        public static string GetStringCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetCertificateProperty<string>(name, CertSrv.PROPTYPE_STRING);
        }

        public static int GetLongCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetCertificateProperty<int>(name, CertSrv.PROPTYPE_LONG);
        }

        public static byte[] GetBinaryCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
            var variantObjectPtr = Marshal.AllocHGlobal(2048);

            try
            {
                // Get VARIANT containing certificate bytes
                // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
                serverPolicy.GetCertificateProperty(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
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

        private static T GetRequestProperty<T>(this ICertServerPolicy serverPolicy, string name, int type)
        {
            var variantObjectPtr = Marshal.AllocHGlobal(2048);

            try
            {
                serverPolicy.GetRequestProperty(name, type, variantObjectPtr);
                var result = (T) Marshal.GetObjectForNativeVariant(variantObjectPtr);
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

        public static DateTimeOffset GetDateRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return new DateTimeOffset(serverPolicy.GetRequestProperty<DateTime>(name, CertSrv.PROPTYPE_DATE)
                .ToUniversalTime());
        }

        public static string GetStringRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetRequestProperty<string>(name, CertSrv.PROPTYPE_STRING);
        }

        public static int GetLongRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetRequestProperty<int>(name, CertSrv.PROPTYPE_LONG);
        }

        public static byte[] GetBinaryRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            // https://blogs.msdn.microsoft.com/alejacma/2008/08/04/how-to-modify-an-interop-assembly-to-change-the-return-type-of-a-method-vb-net/
            var variantObjectPtr = Marshal.AllocHGlobal(2048);

            try
            {
                // Get VARIANT containing certificate bytes
                // Read ANSI BSTR information from the VARIANT as we know RawCertificate property is ANSI BSTR.
                serverPolicy.GetRequestProperty(name, CertSrv.PROPTYPE_BINARY, variantObjectPtr);
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
}