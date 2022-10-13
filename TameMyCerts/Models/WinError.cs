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
    ///     Constants from WinError.h
    /// </summary>
    internal static class WinError
    {
        /// <summary>
        ///     The operation completed successfully.
        /// </summary>
        public const int ERROR_SUCCESS = 0;

        /// <summary>
        ///     The specified time is invalid.
        /// </summary>
        public const int ERROR_INVALID_TIME = 1901;

        /// <summary>
        ///     An internal error occurred.
        /// </summary>
        public const int NTE_FAIL = unchecked((int)0x80090020);

        /// <summary>
        ///     The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
        /// </summary>
        public const int CERTSRV_E_TEMPLATE_DENIED = unchecked((int)0x80094012);

        /// <summary>
        ///     The request subject name is invalid or too long.
        /// </summary>
        public const int CERTSRV_E_BAD_REQUESTSUBJECT = unchecked((int)0x80094001);

        /// <summary>
        ///     The requested certificate template is not supported by this CA.
        /// </summary>
        public const int CERTSRV_E_UNSUPPORTED_CERT_TYPE = unchecked((int)0x80094800);

        /// <summary>
        ///     The public key does not meet the minimum size required by the specified certificate template.
        /// </summary>
        public const int CERTSRV_E_KEY_LENGTH = unchecked((int)0x80094811);

        /// <summary>
        ///     The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded.
        /// </summary>
        public const int CERT_E_INVALID_NAME = unchecked((int)0x800B0114);
    }
}