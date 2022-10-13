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

        public const int ENUM_ENTERPRISE_ROOTCA = 0;
        public const int ENUM_ENTERPRISE_SUBCA = 1;
        public const int ENUM_STANDALONE_ROOTCA = 3;
        public const int ENUM_STANDALONE_SUBCA = 4;

        public const int EDITF_ATTRIBUTEENDDATE = 0x00000020;
        public const int EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000;
    }
}