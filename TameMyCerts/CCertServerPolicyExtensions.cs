// Copyright 2021 Uwe Gradenegger

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
using System.Runtime.InteropServices;
using CERTCLILib;

namespace TameMyCerts
{
    public static class CCertServerPolicyExtensions
    {
        [DllImport(@"oleaut32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern int VariantClear(IntPtr pvarg);

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
                VariantClear(variantObjectPtr);
                Marshal.FreeHGlobal(variantObjectPtr);
            }
        }

        public static DateTime GetDateCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetCertificateProperty<DateTime>(name, CertSrv.PROPTYPE_DATE);
        }

        /// <summary>
        ///     Tries to extract the certificate property out of the <see cref="CCertServerPolicy" /> with the given name.
        ///     Returns the value if successful, otherwise the default.
        /// </summary>
        /// <param name="serverPolicy">The server policy to search for the certificate property.</param>
        /// <param name="name">The name of the certificate property.</param>
        /// <returns>The value of the certificate property or default.</returns>
        public static string GetStringCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetCertificateProperty<string>(name, CertSrv.PROPTYPE_STRING);
        }

        public static long GetLongCertificatePropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetCertificateProperty<long>(name, CertSrv.PROPTYPE_LONG);
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
                VariantClear(variantObjectPtr);
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
                serverPolicy.GetRequestProperty(name, CertSrv.PROPTYPE_DATE, variantObjectPtr);
                var result = (T) Marshal.GetObjectForNativeVariant(variantObjectPtr);
                return result;
            }
            catch
            {
                return default;
            }
            finally
            {
                VariantClear(variantObjectPtr);
                Marshal.FreeHGlobal(variantObjectPtr);
            }
        }

        public static DateTime GetDateRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetRequestProperty<DateTime>(name, CertSrv.PROPTYPE_DATE);
        }

        public static string GetStringRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetRequestProperty<string>(name, CertSrv.PROPTYPE_STRING);
        }

        public static long GetLongRequestPropertyOrDefault(this CCertServerPolicy serverPolicy, string name)
        {
            return serverPolicy.GetRequestProperty<long>(name, CertSrv.PROPTYPE_LONG);
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
                VariantClear(variantObjectPtr);
                Marshal.FreeHGlobal(variantObjectPtr);
            }
        }

        #endregion
    }
}