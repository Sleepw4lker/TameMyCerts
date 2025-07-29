using System.Runtime.InteropServices;
using CERTCLILib;
using CERTEXITLib;
using Microsoft.Win32;
using TameMyCerts.AdcsModules.ExitModule;
using TameMyCerts.AdcsModules.ExitModule.ClassExtensions;
using TameMyCerts.AdcsModules.ExitModule.Enums;

namespace TameMycerts.AdcsModules.ExitModule;

[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("TameMyCerts.Exit")]
[Guid("b4a778fb-3e24-4c85-abc9-25a7f2077201")]
public class Exit : ICertExit2
{
    private string _outputDirectory;

    #region ICertExit2 Members

    public CCertManageExitModule GetManageModule()
    {
        return new ExitManage();
    }

    #endregion

    #region ICertExit Members

    public string GetDescription()
    {
        return "TameMyCerts Exit Module";
    }

    public int Initialize(string strConfig)
    {
        // Load Settings from Registry
        var configRoot =
            $"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{strConfig}";

        _outputDirectory = (string)Registry.GetValue(
            $"{configRoot}\\ExitModules\\TameMyCerts.AdcsModules.ExitModule.Exit",
            "OutputDirectory",
            null
        );

        // Subscribe to the Events we want to process
        return (int)ExitEvents.CertIssued;
    }

    public void Notify(int exitEvent, int context)
    {
        var serverExit = new CCertServerExit();
        serverExit.SetContext(context);

        var dbRow = serverExit.GetDatabaseRow();

        switch (exitEvent)
        {
            case (int)ExitEvents.CertIssued:

                


                break;
        }
    }

    #endregion
}