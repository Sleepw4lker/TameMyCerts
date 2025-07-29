using System.Reflection;
using System.Runtime.InteropServices;
using CERTEXITLib;

namespace TameMyCerts.AdcsModules.ExitModule
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("TameMyCerts.ExitManage")]
    [Guid("fa2cbbd3-a1e9-4800-95fe-63548946a94c")]
    public class ExitManage : CCertManageExitModule
    {
        #region Constructors

        #endregion

        #region ICertManageModule Members

        public void Configure(string strConfig, string strStorageLocation, int flags)
        {
            // This method is intended for future functionality.
        }

        public object GetProperty(string strConfig, string strStorageLocation, string strPropertyName, int flags)
        {
            var assembly = Assembly.GetExecutingAssembly();

            switch (strPropertyName) // Each of these is required
            {
                case "Name":
                    return ((AssemblyTitleAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyTitleAttribute))).Title;

                case "Description":
                    return ((AssemblyDescriptionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyDescriptionAttribute))).Description;

                case "Copyright":
                    return ((AssemblyCopyrightAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyCopyrightAttribute))).Copyright;

                case "File Version":
                    return ((AssemblyFileVersionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyFileVersionAttribute))).Version;

                case "Product Version":
                    return ((AssemblyVersionAttribute) assembly.GetCustomAttribute(
                        typeof(AssemblyVersionAttribute))).Version;

                default:
                    return "Unknown Property: " + strPropertyName;
            }
        }

        public void SetProperty(string strConfig, string strStorageLocation, string strPropertyName, int flags,
            ref object pvarProperty)
        {
            // This method is intended for future functionality.
        }

        #endregion
    }
}