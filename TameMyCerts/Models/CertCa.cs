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
    ///     Constants from CertCa.h
    /// </summary>
    internal static class CertCa
    {
        /// <summary>
        ///     The enrolling application must supply the subject name.
        /// </summary>
        public const int CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1;

        /// <summary>
        ///     This is a machine cert type
        /// </summary>
        public const int CT_FLAG_MACHINE_TYPE = 0x40;
    }
}