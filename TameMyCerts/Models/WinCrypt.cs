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

namespace TameMyCerts.Models
{
    /// <summary>
    ///     Constants from WinCrypt.h
    /// </summary>
    internal static class WinCrypt
    {
        public const string szOID_RSA_RSA = "1.2.840.113549.1.1.1";
        public const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";
        public const string szOID_OS_VERSION = "1.3.6.1.4.1.311.13.2.3";
        public const string szOID_ENROLLMENT_CSP_PROVIDER = "1.3.6.1.4.1.311.13.2.2";
        public const string szOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20";
        public const string szOID_DS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2";
        public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";
    }
}