
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.3928.0
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly CERTEXITLib
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 35 43 43 38 44 43 38 30 2D 43 32 43 38   // ..$5CC8DC80-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ImportedFromTypeLibAttribute::.ctor(string) = ( 01 00 0B 43 45 52 54 45 58 49 54 4C 69 62 00 00 ) // ...CERTEXITLib..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibVersionAttribute::.ctor(int32,
                                                                                                int32) = ( 01 00 01 00 00 00 00 00 00 00 00 00 ) 
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module CERTEXITLib.dll
// MVID: {0EB7F34C-AD51-4088-9D63-761289983BAA}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x073F0000


// =============== CLASS MEMBERS DECLARATION ===================

.class interface public abstract auto ansi import CERTEXITLib.ICertExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 31 39 41 45 31 41 30 2D 37 33 36 34   // ..$E19AE1A0-7364
                                                                                                  2D 31 31 44 30 2D 38 38 31 36 2D 30 30 41 30 43   // -11D0-8816-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit::Initialize

  .method public hidebysig newslot abstract virtual 
          instance void  Notify([in] int32 ExitEvent,
                                [in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit::Notify

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit::GetDescription

} // end of class CERTEXITLib.ICertExit

.class interface public abstract auto ansi import CERTEXITLib.ICertExit2
       implements CERTEXITLib.ICertExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 30 41 42 46 34 38 34 42 2D 44 30 34 39   // ..$0ABF484B-D049
                                                                                                  2D 34 36 34 44 2D 41 37 45 44 2D 35 35 32 45 37   // -464D-A7ED-552E7
                                                                                                  35 32 39 42 30 46 46 00 00 )                      // 529B0FF..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit2::Initialize

  .method public hidebysig newslot abstract virtual 
          instance void  Notify([in] int32 ExitEvent,
                                [in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit2::Notify

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertExit2::GetDescription

  .method public hidebysig newslot abstract virtual 
          instance class CERTEXITLib.CCertManageExitModule 
          marshal( interface ) 
          GetManageModule() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertExit2::GetManageModule

} // end of class CERTEXITLib.ICertExit2

.class interface public abstract auto ansi import CERTEXITLib.CCertExit
       implements CERTEXITLib.ICertExit2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1A 43 45 52 54 45 58 49 54 4C 69 62 2E 43   // ...CERTEXITLib.C
                                                                                                                          43 65 72 74 45 78 69 74 43 6C 61 73 73 00 00 )    // CertExitClass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 30 41 42 46 34 38 34 42 2D 44 30 34 39   // ..$0ABF484B-D049
                                                                                                  2D 34 36 34 44 2D 41 37 45 44 2D 35 35 32 45 37   // -464D-A7ED-552E7
                                                                                                  35 32 39 42 30 46 46 00 00 )                      // 529B0FF..
} // end of class CERTEXITLib.CCertExit

.class public auto ansi import CERTEXITLib.CCertExitClass
       extends [mscorlib]System.Object
       implements CERTEXITLib.ICertExit2,
                  CERTEXITLib.CCertExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 35 43 35 46 36 43 39 30 2D 43 32 43 38   // ..$5C5F6C90-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertExitClass::.ctor

  .method public hidebysig newslot virtual 
          instance int32  Initialize([in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertExit2::Initialize
  } // end of method CCertExitClass::Initialize

  .method public hidebysig newslot virtual 
          instance void  Notify([in] int32 ExitEvent,
                                [in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertExit2::Notify
  } // end of method CCertExitClass::Notify

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetDescription() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertExit2::GetDescription
  } // end of method CCertExitClass::GetDescription

  .method public hidebysig newslot virtual 
          instance class CERTEXITLib.CCertManageExitModule 
          marshal( interface ) 
          GetManageModule() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertExit2::GetManageModule
  } // end of method CCertExitClass::GetManageModule

} // end of class CERTEXITLib.CCertExitClass

.class interface public abstract auto ansi import CERTEXITLib.ICertManageModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 44 37 41 44 34 32 2D 42 44 33 44   // ..$E7D7AD42-BD3D
                                                                                                  2D 31 31 44 31 2D 39 41 34 44 2D 30 30 43 30 34   // -11D1-9A4D-00C04
                                                                                                  46 43 32 39 37 45 42 00 00 )                      // FC297EB..
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

} // end of class CERTEXITLib.ICertManageModule

.class interface public abstract auto ansi import CERTEXITLib.CCertManageExitModule
       implements CERTEXITLib.ICertManageModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 26 43 45 52 54 45 58 49 54 4C 69 62 2E 43   // ..&CERTEXITLib.C
                                                                                                                          43 65 72 74 4D 61 6E 61 67 65 45 78 69 74 4D 6F   // CertManageExitMo
                                                                                                                          64 75 6C 65 43 6C 61 73 73 00 00 )                // duleClass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 45 37 44 37 41 44 34 32 2D 42 44 33 44   // ..$E7D7AD42-BD3D
                                                                                                  2D 31 31 44 31 2D 39 41 34 44 2D 30 30 43 30 34   // -11D1-9A4D-00C04
                                                                                                  46 43 32 39 37 45 42 00 00 )                      // FC297EB..
} // end of class CERTEXITLib.CCertManageExitModule

.class public auto ansi import CERTEXITLib.CCertManageExitModuleClass
       extends [mscorlib]System.Object
       implements CERTEXITLib.ICertManageModule,
                  CERTEXITLib.CCertManageExitModule
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 35 44 32 43 32 46 42 30 2D 43 32 43 38   // ..$5D2C2FB0-C2C8
                                                                                                  2D 31 31 44 32 2D 42 33 31 33 2D 30 30 43 30 34   // -11D2-B313-00C04
                                                                                                  46 37 39 44 43 37 32 00 00 )                      // F79DC72..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertManageExitModuleClass::.ctor

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetProperty([in] string  marshal( bstr) strConfig,
                      [in] string  marshal( bstr) strStorageLocation,
                      [in] string  marshal( bstr) strPropertyName,
                      [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertManageModule::GetProperty
  } // end of method CCertManageExitModuleClass::GetProperty

  .method public hidebysig newslot virtual 
          instance void  SetProperty([in] string  marshal( bstr) strConfig,
                                     [in] string  marshal( bstr) strStorageLocation,
                                     [in] string  marshal( bstr) strPropertyName,
                                     [in] int32 Flags,
                                     [in] object&  marshal( struct) pvarProperty) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertManageModule::SetProperty
  } // end of method CCertManageExitModuleClass::SetProperty

  .method public hidebysig newslot virtual 
          instance void  Configure([in] string  marshal( bstr) strConfig,
                                   [in] string  marshal( bstr) strStorageLocation,
                                   [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTEXITLib.ICertManageModule::Configure
  } // end of method CCertManageExitModuleClass::Configure

} // end of class CERTEXITLib.CCertManageExitModuleClass


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file CERTEXITLIB.res
