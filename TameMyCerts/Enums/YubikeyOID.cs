// Copyright 2021-2024 Uwe Gradenegger <uwe@gradenegger.eu>
// Copyright 2024 Oscar Virot <virot@virot.com>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace TameMyCerts.Enums
{
    /// <summary>
    ///     Constants from Yubico
    ///     https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
    /// </summary>
    internal static class YubikeyOID
    {
        public const string FIRMWARE = "1.3.6.1.4.1.41482.3.3";
        public const string SERIALNUMBER = "1.3.6.1.4.1.41482.3.7";
        public const string PIN_TOUCH_POLICY = "1.3.6.1.4.1.41482.3.8";
        public const string FORMFACTOR = "1.3.6.1.4.1.41482.3.9";
        public const string FIPS_CERTIFIED = "1.3.6.1.4.1.41482.3.10";
        public const string CPSN_CERTIFIED = "1.3.6.1.4.1.41482.3.11";
        public const string ATTESTION_INTERMEDIATE = "1.3.6.1.4.1.41482.3.2";
        public const string ATTESTION_DEVICE = "1.3.6.1.4.1.41482.3.11";
    }
}