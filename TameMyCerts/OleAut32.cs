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

// Kudos to Vadims Podans for his research and support!

using System;
using System.Runtime.InteropServices;

namespace TameMyCerts {
    class OleAut32 {
        public const Int16 VT_BSTR = 0x8;

        [DllImport("OleAut32.dll", SetLastError = true)]
        public static extern Int32 VariantClear(IntPtr pvarg);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VARIANT {
            public Int16 vt;
            public Int16 wReserved1;
            public Int16 wReserved2;
            public Int16 wReserved3;
            public IntPtr pvRecord;
        }
    }
}
