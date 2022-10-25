using System;
using System.Runtime.InteropServices;

namespace TameMyCerts.Enums
{
    // Kudos to Vadims Podans for his research and support!
    internal class OleAut32
    {
        public const short VT_BSTR = 0x8;

        [DllImport("OleAut32.dll", SetLastError = true)]
        public static extern int VariantClear(IntPtr pvarg);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VARIANT
        {
            public short vt;
            public short wReserved1;
            public short wReserved2;
            public short wReserved3;
            public IntPtr pvRecord;
        }
    }
}