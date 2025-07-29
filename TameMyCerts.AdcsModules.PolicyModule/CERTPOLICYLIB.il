
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.3928.0
//  Copyright (c) Microsoft Corporation. Alle Rechte vorbehalten.



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly CERTPOLICYLib
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibVersionAttribute::.ctor(int32,
                                                                                                int32) = ( 01 00 01 00 00 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 41 30 42 37 35 34 30 2D 43 32 43 38   // ..$3A0B7540-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ImportedFromTypeLibAttribute::.ctor(string) = ( 01 00 0D 43 45 52 54 50 4F 4C 49 43 59 4C 69 62   // ...CERTPOLICYLib
                                                                                                                 00 00 ) 
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module CERTPOLICYLib.dll
// MVID: {E1129AE2-FAA4-490B-9546-69BB7452B9B6}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x07020000


// =============== CLASS MEMBERS DECLARATION ===================

.class interface public abstract auto ansi import CERTPOLICYLib.ICertPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 38 42 42 35 41 30 30 2D 37 36 33 36   // ..$38BB5A00-7636
                                                                                                  2D 31 31 44 30 2D 42 34 31 33 2D 30 30 41 30 43   // -11D0-B413-00A0C
                                                                                                  39 31 42 42 46 38 43 00 00 )                      // 91BBF8C..
  .method public hidebysig newslot abstract virtual 
          instance void  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy::Initialize

  .method public hidebysig newslot abstract virtual 
          instance int32  VerifyRequest([in] string  marshal( bstr) strConfig,
                                        [in] int32 Context,
                                        [in] int32 bNewRequest,
                                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy::VerifyRequest

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy::GetDescription

  .method public hidebysig newslot abstract virtual 
          instance void  ShutDown() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy::ShutDown

} // end of class CERTPOLICYLib.ICertPolicy

.class interface public abstract auto ansi import CERTPOLICYLib.ICertPolicy2
       implements CERTPOLICYLib.ICertPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 44 42 34 39 31 30 45 2D 38 30 30 31   // ..$3DB4910E-8001
                                                                                                  2D 34 42 46 31 2D 41 41 31 42 2D 46 34 33 41 38   // -4BF1-AA1B-F43A8
                                                                                                  30 38 33 31 37 41 30 00 00 )                      // 08317A0..
  .method public hidebysig newslot abstract virtual 
          instance void  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy2::Initialize

  .method public hidebysig newslot abstract virtual 
          instance int32  VerifyRequest([in] string  marshal( bstr) strConfig,
                                        [in] int32 Context,
                                        [in] int32 bNewRequest,
                                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy2::VerifyRequest

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy2::GetDescription

  .method public hidebysig newslot abstract virtual 
          instance void  ShutDown() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertPolicy2::ShutDown

  .method public hidebysig newslot abstract virtual 
          instance class CERTPOLICYLib.CCertManagePolicyModule 
          marshal( interface ) 
          GetManageModule() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertPolicy2::GetManageModule

} // end of class CERTPOLICYLib.ICertPolicy2

.class interface public abstract auto ansi import CERTPOLICYLib.CCertPolicy
       implements CERTPOLICYLib.ICertPolicy2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 44 42 34 39 31 30 45 2D 38 30 30 31   // ..$3DB4910E-8001
                                                                                                  2D 34 42 46 31 2D 41 41 31 42 2D 46 34 33 41 38   // -4BF1-AA1B-F43A8
                                                                                                  30 38 33 31 37 41 30 00 00 )                      // 08317A0..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1E 43 45 52 54 50 4F 4C 49 43 59 4C 69 62   // ...CERTPOLICYLib
                                                                                                                          2E 43 43 65 72 74 50 6F 6C 69 63 79 43 6C 61 73   // .CCertPolicyClas
                                                                                                                          73 00 00 )                                        // s..
} // end of class CERTPOLICYLib.CCertPolicy

.class public auto ansi import CERTPOLICYLib.CCertPolicyClass
       extends [mscorlib]System.Object
       implements CERTPOLICYLib.ICertPolicy2,
                  CERTPOLICYLib.CCertPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 42 36 36 35 34 44 30 2D 43 32 43 38   // ..$3B6654D0-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertPolicyClass::.ctor

  .method public hidebysig newslot virtual 
          instance void  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertPolicy2::Initialize
  } // end of method CCertPolicyClass::Initialize

  .method public hidebysig newslot virtual 
          instance int32  VerifyRequest([in] string  marshal( bstr) strConfig,
                                        [in] int32 Context,
                                        [in] int32 bNewRequest,
                                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertPolicy2::VerifyRequest
  } // end of method CCertPolicyClass::VerifyRequest

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertPolicy2::GetDescription
  } // end of method CCertPolicyClass::GetDescription

  .method public hidebysig newslot virtual 
          instance void  ShutDown() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertPolicy2::ShutDown
  } // end of method CCertPolicyClass::ShutDown

  .method public hidebysig newslot virtual 
          instance class CERTPOLICYLib.CCertManagePolicyModule 
          marshal( interface ) 
          GetManageModule() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertPolicy2::GetManageModule
  } // end of method CCertPolicyClass::GetManageModule

} // end of class CERTPOLICYLib.CCertPolicyClass

.class interface public abstract auto ansi import CERTPOLICYLib.ICertManageModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 44 37 41 44 34 32 2D 42 44 33 44   // ..$E7D7AD42-BD3D
                                                                                                  2D 31 31 44 31 2D 39 41 34 44 2D 30 30 43 30 34   // -11D1-9A4D-00C04
                                                                                                  46 43 32 39 37 45 42 00 00 )                      // FC297EB..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetProperty([in] string  marshal( bstr) strConfig,
                      [in] string  marshal( bstr) strStorageLocation,
                      [in] string  marshal( bstr) strPropertyName,
                      [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertManageModule::GetProperty

  .method public hidebysig newslot abstract virtual 
          instance void  SetProperty([in] string  marshal( bstr) strConfig,
                                     [in] string  marshal( bstr) strStorageLocation,
                                     [in] string  marshal( bstr) strPropertyName,
                                     [in] int32 Flags,
                                     [in] object&  marshal( struct) pvarProperty) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertManageModule::SetProperty

  .method public hidebysig newslot abstract virtual 
          instance void  Configure([in] string  marshal( bstr) strConfig,
                                   [in] string  marshal( bstr) strStorageLocation,
                                   [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertManageModule::Configure

} // end of class CERTPOLICYLib.ICertManageModule

.class interface public abstract auto ansi import CERTPOLICYLib.CCertManagePolicyModule
       implements CERTPOLICYLib.ICertManageModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 2A 43 45 52 54 50 4F 4C 49 43 59 4C 69 62   // ..*CERTPOLICYLib
                                                                                                                          2E 43 43 65 72 74 4D 61 6E 61 67 65 50 6F 6C 69   // .CCertManagePoli
                                                                                                                          63 79 4D 6F 64 75 6C 65 43 6C 61 73 73 00 00 )    // cyModuleClass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 44 37 41 44 34 32 2D 42 44 33 44   // ..$E7D7AD42-BD3D
                                                                                                  2D 31 31 44 31 2D 39 41 34 44 2D 30 30 43 30 34   // -11D1-9A4D-00C04
                                                                                                  46 43 32 39 37 45 42 00 00 )                      // FC297EB..
} // end of class CERTPOLICYLib.CCertManagePolicyModule

.class public auto ansi import CERTPOLICYLib.CCertManagePolicyModuleClass
       extends [mscorlib]System.Object
       implements CERTPOLICYLib.ICertManageModule,
                  CERTPOLICYLib.CCertManagePolicyModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 42 42 34 34 33 36 30 2D 43 32 43 38   // ..$3BB44360-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertManagePolicyModuleClass::.ctor

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetProperty([in] string  marshal( bstr) strConfig,
                      [in] string  marshal( bstr) strStorageLocation,
                      [in] string  marshal( bstr) strPropertyName,
                      [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertManageModule::GetProperty
  } // end of method CCertManagePolicyModuleClass::GetProperty

  .method public hidebysig newslot virtual 
          instance void  SetProperty([in] string  marshal( bstr) strConfig,
                                     [in] string  marshal( bstr) strStorageLocation,
                                     [in] string  marshal( bstr) strPropertyName,
                                     [in] int32 Flags,
                                     [in] object&  marshal( struct) pvarProperty) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertManageModule::SetProperty
  } // end of method CCertManagePolicyModuleClass::SetProperty

  .method public hidebysig newslot virtual 
          instance void  Configure([in] string  marshal( bstr) strConfig,
                                   [in] string  marshal( bstr) strStorageLocation,
                                   [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTPOLICYLib.ICertManageModule::Configure
  } // end of method CCertManagePolicyModuleClass::Configure

} // end of class CERTPOLICYLib.CCertManagePolicyModuleClass


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// Warnung: Win32-Ressourcendatei "CERTPOLICYLIB.res" wurde erstellt.
