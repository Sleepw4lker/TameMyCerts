
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.3928.0
//  Copyright (c) Microsoft Corporation. Alle Rechte vorbehalten.



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly CERTCLILib
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.ImportedFromTypeLibAttribute::.ctor(string) = ( 01 00 0A 43 45 52 54 43 4C 49 4C 69 62 00 00 )    // ...CERTCLILib..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 37 32 46 43 45 33 32 2D 34 33 32 34   // ..$372FCE32-4324
                                                                                                  2D 31 31 44 30 2D 38 38 31 30 2D 30 30 41 30 43   // -11D0-8810-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibVersionAttribute::.ctor(int32,
                                                                                                int32) = ( 01 00 01 00 00 00 00 00 00 00 00 00 ) 
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module CERTCLILib.dll
// MVID: {C9EBF003-E9A0-49B8-BBFE-DA0BDF77D064}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x06C10000


// =============== CLASS MEMBERS DECLARATION ===================

.class interface public abstract auto ansi import CERTCLILib.ICertGetConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 43 37 45 41 30 39 43 30 2D 43 45 31 37   // ..$C7EA09C0-CE17
                                                                                                  2D 31 31 44 30 2D 38 38 33 33 2D 30 30 41 30 43   // -11D0-8833-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetConfig([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertGetConfig::GetConfig

} // end of class CERTCLILib.ICertGetConfig

.class interface public abstract auto ansi import CERTCLILib.CCertGetConfig
       implements CERTCLILib.ICertGetConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1E 43 45 52 54 43 4C 49 4C 69 62 2E 43 43   // ...CERTCLILib.CC
                                                                                                                          65 72 74 47 65 74 43 6F 6E 66 69 67 43 6C 61 73   // ertGetConfigClas
                                                                                                                          73 00 00 )                                        // s..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 43 37 45 41 30 39 43 30 2D 43 45 31 37   // ..$C7EA09C0-CE17
                                                                                                  2D 31 31 44 30 2D 38 38 33 33 2D 30 30 41 30 43   // -11D0-8833-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
} // end of class CERTCLILib.CCertGetConfig

.class public auto ansi import CERTCLILib.CCertGetConfigClass
       extends [mscorlib]System.Object
       implements CERTCLILib.ICertGetConfig,
                  CERTCLILib.CCertGetConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 43 36 43 43 34 39 42 30 2D 43 45 31 37   // ..$C6CC49B0-CE17
                                                                                                  2D 31 31 44 30 2D 38 38 33 33 2D 30 30 41 30 43   // -11D0-8833-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertGetConfigClass::.ctor

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetConfig([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertGetConfig::GetConfig
  } // end of method CCertGetConfigClass::GetConfig

} // end of class CERTCLILib.CCertGetConfigClass

.class interface public abstract auto ansi import CERTCLILib.ICertConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 37 32 46 43 45 33 34 2D 34 33 32 34   // ..$372FCE34-4324
                                                                                                  2D 31 31 44 30 2D 38 38 31 30 2D 30 30 41 30 43   // -11D0-8810-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public hidebysig newslot abstract virtual 
          instance int32  Reset([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig::Reset

  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig::Next

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetField([in] string  marshal( bstr) strFieldName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig::GetField

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetConfig([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig::GetConfig

} // end of class CERTCLILib.ICertConfig

.class interface public abstract auto ansi import CERTCLILib.ICertConfig2
       implements CERTCLILib.ICertConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 41 31 38 45 44 44 45 2D 37 45 37 38   // ..$7A18EDDE-7E78
                                                                                                  2D 34 31 36 33 2D 38 44 45 44 2D 37 38 45 32 43   // -4163-8DED-78E2C
                                                                                                  39 43 45 45 39 32 34 00 00 )                      // 9CEE924..
  .method public hidebysig newslot abstract virtual 
          instance int32  Reset([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig2::Reset

  .method public hidebysig newslot abstract virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig2::Next

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetField([in] string  marshal( bstr) strFieldName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig2::GetField

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetConfig([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertConfig2::GetConfig

  .method public hidebysig newslot abstract virtual 
          instance void  SetSharedFolder([in] string  marshal( bstr) strSharedFolder) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertConfig2::SetSharedFolder

} // end of class CERTCLILib.ICertConfig2

.class interface public abstract auto ansi import CERTCLILib.CCertConfig
       implements CERTCLILib.ICertConfig2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1B 43 45 52 54 43 4C 49 4C 69 62 2E 43 43   // ...CERTCLILib.CC
                                                                                                                          65 72 74 43 6F 6E 66 69 67 43 6C 61 73 73 00 00 ) // ertConfigClass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 41 31 38 45 44 44 45 2D 37 45 37 38   // ..$7A18EDDE-7E78
                                                                                                  2D 34 31 36 33 2D 38 44 45 44 2D 37 38 45 32 43   // -4163-8DED-78E2C
                                                                                                  39 43 45 45 39 32 34 00 00 )                      // 9CEE924..
} // end of class CERTCLILib.CCertConfig

.class public auto ansi import CERTCLILib.CCertConfigClass
       extends [mscorlib]System.Object
       implements CERTCLILib.ICertConfig2,
                  CERTCLILib.CCertConfig
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 37 32 46 43 45 33 38 2D 34 33 32 34   // ..$372FCE38-4324
                                                                                                  2D 31 31 44 30 2D 38 38 31 30 2D 30 30 41 30 43   // -11D0-8810-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertConfigClass::.ctor

  .method public hidebysig newslot virtual 
          instance int32  Reset([in] int32 Index) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertConfig2::Reset
  } // end of method CCertConfigClass::Reset

  .method public hidebysig newslot virtual 
          instance int32  Next() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertConfig2::Next
  } // end of method CCertConfigClass::Next

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetField([in] string  marshal( bstr) strFieldName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertConfig2::GetField
  } // end of method CCertConfigClass::GetField

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetConfig([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertConfig2::GetConfig
  } // end of method CCertConfigClass::GetConfig

  .method public hidebysig newslot virtual 
          instance void  SetSharedFolder([in] string  marshal( bstr) strSharedFolder) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertConfig2::SetSharedFolder
  } // end of method CCertConfigClass::SetSharedFolder

} // end of class CERTCLILib.CCertConfigClass

.class interface public abstract auto ansi import CERTCLILib.ICertRequest
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 30 31 34 45 34 38 34 30 2D 35 35 32 33   // ..$014E4840-5523
                                                                                                  2D 31 31 44 30 2D 38 38 31 32 2D 30 30 41 30 43   // -11D0-8812-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .method public hidebysig newslot abstract virtual 
          instance int32  Submit([in] int32 Flags,
                                 [in] string  marshal( bstr) strRequest,
                                 [in] string  marshal( bstr) strAttributes,
                                 [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::Submit

  .method public hidebysig newslot abstract virtual 
          instance int32  RetrievePending([in] int32 RequestId,
                                          [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::RetrievePending

  .method public hidebysig newslot abstract virtual 
          instance int32  GetLastStatus() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::GetLastStatus

  .method public hidebysig newslot abstract virtual 
          instance int32  GetRequestId() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::GetRequestId

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDispositionMessage() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::GetDispositionMessage

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCACertificate([in] int32 fExchangeCertificate,
                           [in] string  marshal( bstr) strConfig,
                           [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::GetCACertificate

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCertificate([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest::GetCertificate

} // end of class CERTCLILib.ICertRequest

.class interface public abstract auto ansi import CERTCLILib.ICertRequest2
       implements CERTCLILib.ICertRequest
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 34 37 37 32 39 38 38 2D 34 41 38 35   // ..$A4772988-4A85
                                                                                                  2D 34 46 41 39 2D 38 32 34 45 2D 42 35 43 46 35   // -4FA9-824E-B5CF5
                                                                                                  43 31 36 34 30 35 41 00 00 )                      // C16405A..
  .method public hidebysig newslot abstract virtual 
          instance int32  Submit([in] int32 Flags,
                                 [in] string  marshal( bstr) strRequest,
                                 [in] string  marshal( bstr) strAttributes,
                                 [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::Submit

  .method public hidebysig newslot abstract virtual 
          instance int32  RetrievePending([in] int32 RequestId,
                                          [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::RetrievePending

  .method public hidebysig newslot abstract virtual 
          instance int32  GetLastStatus() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetLastStatus

  .method public hidebysig newslot abstract virtual 
          instance int32  GetRequestId() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetRequestId

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDispositionMessage() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetDispositionMessage

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCACertificate([in] int32 fExchangeCertificate,
                           [in] string  marshal( bstr) strConfig,
                           [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetCACertificate

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCertificate([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetCertificate

  .method public hidebysig newslot abstract virtual 
          instance int32  GetIssuedCertificate([in] string  marshal( bstr) strConfig,
                                               [in] int32 RequestId,
                                               [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetIssuedCertificate

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetErrorMessageText([in] int32 hrMessage,
                              [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetErrorMessageText

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCAProperty([in] string  marshal( bstr) strConfig,
                        [in] int32 PropId,
                        [in] int32 PropIndex,
                        [in] int32 PropType,
                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetCAProperty

  .method public hidebysig newslot abstract virtual 
          instance int32  GetCAPropertyFlags([in] string  marshal( bstr) strConfig,
                                             [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetCAPropertyFlags

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCAPropertyDisplayName([in] string  marshal( bstr) strConfig,
                                   [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetCAPropertyDisplayName

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetFullResponseProperty([in] int32 PropId,
                                  [in] int32 PropIndex,
                                  [in] int32 PropType,
                                  [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest2::GetFullResponseProperty

} // end of class CERTCLILib.ICertRequest2

.class interface public abstract auto ansi import CERTCLILib.ICertRequest3
       implements CERTCLILib.ICertRequest2
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 46 43 38 46 39 32 42 2D 33 33 41 32   // ..$AFC8F92B-33A2
                                                                                                  2D 34 38 36 31 2D 42 46 33 36 2D 32 39 33 33 42   // -4861-BF36-2933B
                                                                                                  37 43 44 36 37 42 33 00 00 )                      // 7CD67B3..
  .method public hidebysig newslot abstract virtual 
          instance int32  Submit([in] int32 Flags,
                                 [in] string  marshal( bstr) strRequest,
                                 [in] string  marshal( bstr) strAttributes,
                                 [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::Submit

  .method public hidebysig newslot abstract virtual 
          instance int32  RetrievePending([in] int32 RequestId,
                                          [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::RetrievePending

  .method public hidebysig newslot abstract virtual 
          instance int32  GetLastStatus() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetLastStatus

  .method public hidebysig newslot abstract virtual 
          instance int32  GetRequestId() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetRequestId

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetDispositionMessage() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetDispositionMessage

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCACertificate([in] int32 fExchangeCertificate,
                           [in] string  marshal( bstr) strConfig,
                           [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetCACertificate

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCertificate([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetCertificate

  .method public hidebysig newslot abstract virtual 
          instance int32  GetIssuedCertificate([in] string  marshal( bstr) strConfig,
                                               [in] int32 RequestId,
                                               [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetIssuedCertificate

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetErrorMessageText([in] int32 hrMessage,
                              [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetErrorMessageText

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCAProperty([in] string  marshal( bstr) strConfig,
                        [in] int32 PropId,
                        [in] int32 PropIndex,
                        [in] int32 PropType,
                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetCAProperty

  .method public hidebysig newslot abstract virtual 
          instance int32  GetCAPropertyFlags([in] string  marshal( bstr) strConfig,
                                             [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetCAPropertyFlags

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetCAPropertyDisplayName([in] string  marshal( bstr) strConfig,
                                   [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetCAPropertyDisplayName

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetFullResponseProperty([in] int32 PropId,
                                  [in] int32 PropIndex,
                                  [in] int32 PropType,
                                  [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 03 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetFullResponseProperty

  .method public hidebysig newslot abstract virtual 
          instance void  SetCredential([in] int32 hWnd,
                                       [in] valuetype CERTCLILib.X509EnrollmentAuthFlags AuthType,
                                       [in] string  marshal( bstr) strCredential,
                                       [in] string  marshal( bstr) strPassword) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 04 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::SetCredential

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetRequestIdString() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 04 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetRequestIdString

  .method public hidebysig newslot abstract virtual 
          instance int32  GetIssuedCertificate2([in] string  marshal( bstr) strConfig,
                                                [in] string  marshal( bstr) strRequestId,
                                                [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 04 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetIssuedCertificate2

  .method public hidebysig newslot abstract virtual 
          instance bool  GetRefreshPolicy() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 04 60 00 00 )                         // .....`..
  } // end of method ICertRequest3::GetRefreshPolicy

} // end of class CERTCLILib.ICertRequest3

.class interface public abstract auto ansi import CERTCLILib.CCertRequest
       implements CERTCLILib.ICertRequest3
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 46 43 38 46 39 32 42 2D 33 33 41 32   // ..$AFC8F92B-33A2
                                                                                                  2D 34 38 36 31 2D 42 46 33 36 2D 32 39 33 33 42   // -4861-BF36-2933B
                                                                                                  37 43 44 36 37 42 33 00 00 )                      // 7CD67B3..
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1C 43 45 52 54 43 4C 49 4C 69 62 2E 43 43   // ...CERTCLILib.CC
                                                                                                                          65 72 74 52 65 71 75 65 73 74 43 6C 61 73 73 00   // ertRequestClass.
                                                                                                                          00 ) 
} // end of class CERTCLILib.CCertRequest

.class public auto ansi import CERTCLILib.CCertRequestClass
       extends [mscorlib]System.Object
       implements CERTCLILib.ICertRequest3,
                  CERTCLILib.CCertRequest
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 39 38 41 46 46 33 46 30 2D 35 35 32 34   // ..$98AFF3F0-5524
                                                                                                  2D 31 31 44 30 2D 38 38 31 32 2D 30 30 41 30 43   // -11D0-8812-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertRequestClass::.ctor

  .method public hidebysig newslot virtual 
          instance int32  Submit([in] int32 Flags,
                                 [in] string  marshal( bstr) strRequest,
                                 [in] string  marshal( bstr) strAttributes,
                                 [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::Submit
  } // end of method CCertRequestClass::Submit

  .method public hidebysig newslot virtual 
          instance int32  RetrievePending([in] int32 RequestId,
                                          [in] string  marshal( bstr) strConfig) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::RetrievePending
  } // end of method CCertRequestClass::RetrievePending

  .method public hidebysig newslot virtual 
          instance int32  GetLastStatus() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetLastStatus
  } // end of method CCertRequestClass::GetLastStatus

  .method public hidebysig newslot virtual 
          instance int32  GetRequestId() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetRequestId
  } // end of method CCertRequestClass::GetRequestId

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetDispositionMessage() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetDispositionMessage
  } // end of method CCertRequestClass::GetDispositionMessage

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetCACertificate([in] int32 fExchangeCertificate,
                           [in] string  marshal( bstr) strConfig,
                           [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetCACertificate
  } // end of method CCertRequestClass::GetCACertificate

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetCertificate([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetCertificate
  } // end of method CCertRequestClass::GetCertificate

  .method public hidebysig newslot virtual 
          instance int32  GetIssuedCertificate([in] string  marshal( bstr) strConfig,
                                               [in] int32 RequestId,
                                               [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetIssuedCertificate
  } // end of method CCertRequestClass::GetIssuedCertificate

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetErrorMessageText([in] int32 hrMessage,
                              [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetErrorMessageText
  } // end of method CCertRequestClass::GetErrorMessageText

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCAProperty([in] string  marshal( bstr) strConfig,
                        [in] int32 PropId,
                        [in] int32 PropIndex,
                        [in] int32 PropType,
                        [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetCAProperty
  } // end of method CCertRequestClass::GetCAProperty

  .method public hidebysig newslot virtual 
          instance int32  GetCAPropertyFlags([in] string  marshal( bstr) strConfig,
                                             [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetCAPropertyFlags
  } // end of method CCertRequestClass::GetCAPropertyFlags

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetCAPropertyDisplayName([in] string  marshal( bstr) strConfig,
                                   [in] int32 PropId) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetCAPropertyDisplayName
  } // end of method CCertRequestClass::GetCAPropertyDisplayName

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetFullResponseProperty([in] int32 PropId,
                                  [in] int32 PropIndex,
                                  [in] int32 PropType,
                                  [in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 03 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetFullResponseProperty
  } // end of method CCertRequestClass::GetFullResponseProperty

  .method public hidebysig newslot virtual 
          instance void  SetCredential([in] int32 hWnd,
                                       [in] valuetype CERTCLILib.X509EnrollmentAuthFlags AuthType,
                                       [in] string  marshal( bstr) strCredential,
                                       [in] string  marshal( bstr) strPassword) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 04 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::SetCredential
  } // end of method CCertRequestClass::SetCredential

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetRequestIdString() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 04 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetRequestIdString
  } // end of method CCertRequestClass::GetRequestIdString

  .method public hidebysig newslot virtual 
          instance int32  GetIssuedCertificate2([in] string  marshal( bstr) strConfig,
                                                [in] string  marshal( bstr) strRequestId,
                                                [in] string  marshal( bstr) strSerialNumber) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 04 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetIssuedCertificate2
  } // end of method CCertRequestClass::GetIssuedCertificate2

  .method public hidebysig newslot virtual 
          instance bool  GetRefreshPolicy() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 04 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertRequest3::GetRefreshPolicy
  } // end of method CCertRequestClass::GetRefreshPolicy

} // end of class CERTCLILib.CCertRequestClass

.class interface public abstract auto ansi import CERTCLILib.ICertServerPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 41 30 30 30 39 32 32 2D 46 46 42 45   // ..$AA000922-FFBE
                                                                                                  2D 31 31 43 46 2D 38 38 30 30 2D 30 30 41 30 43   // -11CF-8800-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public hidebysig newslot abstract virtual 
          instance void  SetContext([in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::SetContext

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetRequestProperty([in] string  marshal( bstr) strPropertyName,
                             [in] int32 PropertyType,
                             [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::GetRequestProperty

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetRequestAttribute([in] string  marshal( bstr) strAttributeName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::GetRequestAttribute

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                 [in] int32 PropertyType,
								                 [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::GetCertificateProperty

  .method public hidebysig newslot abstract virtual 
          instance void  SetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                                [in] int32 PropertyType,
                                                [in] object&  marshal( struct) pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::SetCertificateProperty

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                  [in] int32 Type,
                                  [out] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::GetCertificateExtension

  .method public hidebysig newslot abstract virtual 
          instance int32  GetCertificateExtensionFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::GetCertificateExtensionFlags

  .method public hidebysig newslot abstract virtual 
          instance void  SetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                                 [in] int32 Type,
                                                 [in] int32 ExtFlags,
                                                 [in] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::SetCertificateExtension

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateExtensionsSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateExtensionsSetup

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          EnumerateExtensions() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateExtensions

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateExtensionsClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateExtensionsClose

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateAttributesSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateAttributesSetup

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          EnumerateAttributes() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0C 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateAttributes

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateAttributesClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerPolicy::EnumerateAttributesClose

} // end of class CERTCLILib.ICertServerPolicy

.class interface public abstract auto ansi import CERTCLILib.CCertServerPolicy
       implements CERTCLILib.ICertServerPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 21 43 45 52 54 43 4C 49 4C 69 62 2E 43 43   // ..!CERTCLILib.CC
                                                                                                                          65 72 74 53 65 72 76 65 72 50 6F 6C 69 63 79 43   // ertServerPolicyC
                                                                                                                          6C 61 73 73 00 00 )                               // lass..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 41 30 30 30 39 32 32 2D 46 46 42 45   // ..$AA000922-FFBE
                                                                                                  2D 31 31 43 46 2D 38 38 30 30 2D 30 30 41 30 43   // -11CF-8800-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
} // end of class CERTCLILib.CCertServerPolicy

.class public auto ansi import CERTCLILib.CCertServerPolicyClass
       extends [mscorlib]System.Object
       implements CERTCLILib.ICertServerPolicy,
                  CERTCLILib.CCertServerPolicy
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 41 41 30 30 30 39 32 36 2D 46 46 42 45   // ..$AA000926-FFBE
                                                                                                  2D 31 31 43 46 2D 38 38 30 30 2D 30 30 41 30 43   // -11CF-8800-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertServerPolicyClass::.ctor

  .method public hidebysig newslot virtual 
          instance void  SetContext([in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::SetContext
  } // end of method CCertServerPolicyClass::SetContext

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetRequestProperty([in] string  marshal( bstr) strPropertyName,
                             [in] int32 PropertyType,
                             [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::GetRequestProperty
  } // end of method CCertServerPolicyClass::GetRequestProperty

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetRequestAttribute([in] string  marshal( bstr) strAttributeName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::GetRequestAttribute
  } // end of method CCertServerPolicyClass::GetRequestAttribute

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                 [in] int32 PropertyType,
								                 [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::GetCertificateProperty
  } // end of method CCertServerPolicyClass::GetCertificateProperty

  .method public hidebysig newslot virtual 
          instance void  SetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                                [in] int32 PropertyType,
                                                [in] object&  marshal( struct) pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::SetCertificateProperty
  } // end of method CCertServerPolicyClass::SetCertificateProperty

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                  [in] int32 Type,
                                  [out] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::GetCertificateExtension
  } // end of method CCertServerPolicyClass::GetCertificateExtension

  .method public hidebysig newslot virtual 
          instance int32  GetCertificateExtensionFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::GetCertificateExtensionFlags
  } // end of method CCertServerPolicyClass::GetCertificateExtensionFlags

  .method public hidebysig newslot virtual 
          instance void  SetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                                 [in] int32 Type,
                                                 [in] int32 ExtFlags,
                                                 [in] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::SetCertificateExtension
  } // end of method CCertServerPolicyClass::SetCertificateExtension

  .method public hidebysig newslot virtual 
          instance void  EnumerateExtensionsSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateExtensionsSetup
  } // end of method CCertServerPolicyClass::EnumerateExtensionsSetup

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          EnumerateExtensions() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateExtensions
  } // end of method CCertServerPolicyClass::EnumerateExtensions

  .method public hidebysig newslot virtual 
          instance void  EnumerateExtensionsClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateExtensionsClose
  } // end of method CCertServerPolicyClass::EnumerateExtensionsClose

  .method public hidebysig newslot virtual 
          instance void  EnumerateAttributesSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateAttributesSetup
  } // end of method CCertServerPolicyClass::EnumerateAttributesSetup

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          EnumerateAttributes() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0C 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateAttributes
  } // end of method CCertServerPolicyClass::EnumerateAttributes

  .method public hidebysig newslot virtual 
          instance void  EnumerateAttributesClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0D 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerPolicy::EnumerateAttributesClose
  } // end of method CCertServerPolicyClass::EnumerateAttributesClose

} // end of class CERTCLILib.CCertServerPolicyClass

.class interface public abstract auto ansi import CERTCLILib.ICertServerExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 40 10 00 00 00 00 )                         // ..@.....
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 34 42 41 39 45 42 39 30 2D 37 33 32 43   // ..$4BA9EB90-732C
                                                                                                  2D 31 31 44 30 2D 38 38 31 36 2D 30 30 41 30 43   // -11D0-8816-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .method public hidebysig newslot abstract virtual 
          instance void  SetContext([in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::SetContext

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetRequestProperty([in] string  marshal( bstr) strPropertyName,
                             [in] int32 PropertyType,
                             [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::GetRequestProperty

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          GetRequestAttribute([in] string  marshal( bstr) strAttributeName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::GetRequestAttribute

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                 [in] int32 PropertyType,
								                 [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::GetCertificateProperty

  .method public hidebysig newslot abstract virtual 
          instance object 
          marshal( struct) 
          GetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                  [in] int32 Type,
                                  [out] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::GetCertificateExtension

  .method public hidebysig newslot abstract virtual 
          instance int32  GetCertificateExtensionFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::GetCertificateExtensionFlags

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateExtensionsSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateExtensionsSetup

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          EnumerateExtensions() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateExtensions

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateExtensionsClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateExtensionsClose

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateAttributesSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateAttributesSetup

  .method public hidebysig newslot abstract virtual 
          instance string 
          marshal( bstr) 
          EnumerateAttributes() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateAttributes

  .method public hidebysig newslot abstract virtual 
          instance void  EnumerateAttributesClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 02 60 00 00 )                         // .....`..
  } // end of method ICertServerExit::EnumerateAttributesClose

} // end of class CERTCLILib.ICertServerExit

.class interface public abstract auto ansi import CERTCLILib.CCertServerExit
       implements CERTCLILib.ICertServerExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.CoClassAttribute::.ctor(class [mscorlib]System.Type) = ( 01 00 1F 43 45 52 54 43 4C 49 4C 69 62 2E 43 43   // ...CERTCLILib.CC
                                                                                                                          65 72 74 53 65 72 76 65 72 45 78 69 74 43 6C 61   // ertServerExitCla
                                                                                                                          73 73 00 00 )                                     // ss..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 34 42 41 39 45 42 39 30 2D 37 33 32 43   // ..$4BA9EB90-732C
                                                                                                  2D 31 31 44 30 2D 38 38 31 36 2D 30 30 41 30 43   // -11D0-8816-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
} // end of class CERTCLILib.CCertServerExit

.class public auto ansi import CERTCLILib.CCertServerExitClass
       extends [mscorlib]System.Object
       implements CERTCLILib.ICertServerExit,
                  CERTCLILib.CCertServerExit
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 34 43 34 41 35 45 34 30 2D 37 33 32 43   // ..$4C4A5E40-732C
                                                                                                  2D 31 31 44 30 2D 38 38 31 36 2D 30 30 41 30 43   // -11D0-8816-00A0C
                                                                                                  39 30 33 42 38 33 43 00 00 )                      // 903B83C..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.TypeLibTypeAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.TypeLibTypeFlags) = ( 01 00 02 00 00 00 00 00 ) 
  .method public specialname rtspecialname 
          instance void  .ctor() runtime managed internalcall
  {
  } // end of method CCertServerExitClass::.ctor

  .method public hidebysig newslot virtual 
          instance void  SetContext([in] int32 Context) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 00 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::SetContext
  } // end of method CCertServerExitClass::SetContext

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetRequestProperty([in] string  marshal( bstr) strPropertyName,
                             [in] int32 PropertyType,
                             [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 01 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::GetRequestProperty
  } // end of method CCertServerExitClass::GetRequestProperty

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          GetRequestAttribute([in] string  marshal( bstr) strAttributeName) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 02 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::GetRequestAttribute
  } // end of method CCertServerExitClass::GetRequestAttribute

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCertificateProperty([in] string  marshal( bstr) strPropertyName,
                                 [in] int32 PropertyType,
								                 [out] native int pvarPropertyValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 03 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::GetCertificateProperty
  } // end of method CCertServerExitClass::GetCertificateProperty

  .method public hidebysig newslot virtual 
          instance object 
          marshal( struct) 
          GetCertificateExtension([in] string  marshal( bstr) strExtensionName,
                                  [in] int32 Type,
                                  [out] native int pvarValue) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 04 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::GetCertificateExtension
  } // end of method CCertServerExitClass::GetCertificateExtension

  .method public hidebysig newslot virtual 
          instance int32  GetCertificateExtensionFlags() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 05 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::GetCertificateExtensionFlags
  } // end of method CCertServerExitClass::GetCertificateExtensionFlags

  .method public hidebysig newslot virtual 
          instance void  EnumerateExtensionsSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 06 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateExtensionsSetup
  } // end of method CCertServerExitClass::EnumerateExtensionsSetup

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          EnumerateExtensions() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 07 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateExtensions
  } // end of method CCertServerExitClass::EnumerateExtensions

  .method public hidebysig newslot virtual 
          instance void  EnumerateExtensionsClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 08 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateExtensionsClose
  } // end of method CCertServerExitClass::EnumerateExtensionsClose

  .method public hidebysig newslot virtual 
          instance void  EnumerateAttributesSetup([in] int32 Flags) runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 09 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateAttributesSetup
  } // end of method CCertServerExitClass::EnumerateAttributesSetup

  .method public hidebysig newslot virtual 
          instance string 
          marshal( bstr) 
          EnumerateAttributes() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0A 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateAttributes
  } // end of method CCertServerExitClass::EnumerateAttributes

  .method public hidebysig newslot virtual 
          instance void  EnumerateAttributesClose() runtime managed internalcall
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.DispIdAttribute::.ctor(int32) = ( 01 00 0B 00 02 60 00 00 )                         // .....`..
    .override CERTCLILib.ICertServerExit::EnumerateAttributesClose
  } // end of method CCertServerExitClass::EnumerateAttributesClose

} // end of class CERTCLILib.CCertServerExitClass

.class public auto ansi sealed CERTCLILib.X509EnrollmentAuthFlags
       extends [mscorlib]System.Enum
{
  .field public specialname rtspecialname int32 value__
  .field public static literal valuetype CERTCLILib.X509EnrollmentAuthFlags X509AuthNone = int32(0x00000000)
  .field public static literal valuetype CERTCLILib.X509EnrollmentAuthFlags X509AuthAnonymous = int32(0x00000001)
  .field public static literal valuetype CERTCLILib.X509EnrollmentAuthFlags X509AuthKerberos = int32(0x00000002)
  .field public static literal valuetype CERTCLILib.X509EnrollmentAuthFlags X509AuthUsername = int32(0x00000004)
  .field public static literal valuetype CERTCLILib.X509EnrollmentAuthFlags X509AuthCertificate = int32(0x00000008)
} // end of class CERTCLILib.X509EnrollmentAuthFlags


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// Warnung: Win32-Ressourcendatei "CERTCLILIB.res" wurde erstellt.
