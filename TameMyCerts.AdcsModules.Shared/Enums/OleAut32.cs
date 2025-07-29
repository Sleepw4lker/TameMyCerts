using System;
using System.Runtime.InteropServices;

namespace TameMyCerts.AdcsModules.Shared.Enums;

// Kudos to Vadims Podans for his research and support!
public class OleAut32
{
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