// Copyright 2021 Uwe Gradenegger

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using CERTCLILib;
using CERTPOLICYLib;
using Microsoft.Win32;

namespace TameMyCerts
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("TameMyCerts.Policy")]
    [Guid("432413c6-2e86-4667-9697-c1e038877ef9")] // must be distinct from PolicyManage Class
    public class Policy : ICertPolicy2
    {
        private readonly string _appName;
        private readonly string _appVersion;
        private readonly TemplateInfo _templateInfo = new TemplateInfo();
        private Logger _logger;
        private string _policyDirectory;
        private dynamic _windowsDefaultPolicyModule;

        public Policy()
        {
            var assembly = Assembly.GetExecutingAssembly();

            _appName = ((AssemblyTitleAttribute) assembly.GetCustomAttribute(
                typeof(AssemblyTitleAttribute))).Title;

            _appVersion = ((AssemblyFileVersionAttribute) assembly.GetCustomAttribute(
                typeof(AssemblyFileVersionAttribute))).Version;
        }

        #region ICertPolicy2 Members

        public CCertManagePolicyModule GetManageModule()
        {
            return new PolicyManage();
        }

        #endregion

        #region ICertPolicy Members

        public string GetDescription()
        {
            return _appName;
        }

        public void Initialize(string strConfig)
        {
            const string windowsDefaultPolicyModuleGuid = "3B6654D0-C2C8-11D2-B313-00C04F79DC72";
            const string configRoot =
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration";

            // Initialize Event Log
            var logLevel = (int) Registry.GetValue(
                $"{configRoot}\\{strConfig}",
                "LogLevel",
                CertSrv.CERTLOG_WARNING
            );

            _logger = new Logger(_appName, logLevel);

            // Prevent the usage on a standalone CA
            var caType = (int) Registry.GetValue(
                $"{configRoot}\\{strConfig}",
                "CAType",
                CertSrv.ENUM_STANDALONE_ROOTCA
            );

            if (!(caType == CertSrv.ENUM_ENTERPRISE_ROOTCA || caType == CertSrv.ENUM_ENTERPRISE_SUBCA))
            {
                _logger.Log(Events.MODULE_NOT_SUPPORTED, _appName);

                // Abort loading the policy module.
                throw new NotSupportedException();
            }

            // Load Settings from Registry
            _policyDirectory = (string) Registry.GetValue(
                $"{configRoot}\\{strConfig}\\PolicyModules\\{_appName}.Policy",
                "PolicyDirectory",
                Path.GetTempPath()
            );

            // Load the Windows default default policy module
            try
            {
                var windowsDefaultPolicyModuleType = Type.GetTypeFromCLSID(
                    new Guid(windowsDefaultPolicyModuleGuid),
                    true
                );

                _windowsDefaultPolicyModule = Activator.CreateInstance(windowsDefaultPolicyModuleType);

                _windowsDefaultPolicyModule.GetType().InvokeMember(
                    "Initialize",
                    BindingFlags.InvokeMethod,
                    null,
                    _windowsDefaultPolicyModule,
                    new object[] {strConfig}
                );

                _logger.Log(Events.PDEF_SUCCESS_INIT, _appName, _appVersion);
            }
            catch (Exception ex)
            {
                _logger.Log(Events.PDEF_FAIL_INIT, ex);

                // Abort loading the policy module. This will cause the certification authority service to fail
                throw;
            }
        }

        public int VerifyRequest(string strConfig, int context, int bNewRequest, int flags)
        {
            int result;

            var certServerPolicy = new CCertServerPolicy();

            certServerPolicy.SetContext(context);

            var requestId = (int) certServerPolicy.GetLongRequestPropertyOrDefault("RequestId");

            // Hand the request over to the Windows Default policy module
            try
            {
                result = (int) _windowsDefaultPolicyModule.GetType().InvokeMember(
                    "VerifyRequest",
                    BindingFlags.InvokeMethod,
                    null,
                    _windowsDefaultPolicyModule,
                    new object[] {strConfig, context, bNewRequest, flags}
                );
            }
            catch (Exception ex)
            {
                if (ex.InnerException is COMException)
                {
                    _logger.Log(Events.PDEF_FAIL_VERIFY, requestId, ex);

                    // Some reasons to deny a request come in form of COM Exceptions
                    // If so, we're done here and hand the HResult back to the CA process
                    return ex.InnerException.HResult;
                }

                _logger.Log(Events.PDEF_FAIL_VERIFY, requestId, ex);

                return CertSrv.VR_INSTANT_BAD;
            }

            // We don't question if the default policy module decided to deny the request
            // Note that a policy module can also return any HResult code as defined in winerr.h
            if (!(result == CertSrv.VR_PENDING || result == CertSrv.VR_INSTANT_OK))
            {
                _logger.Log(Events.PDEF_REQUEST_DENIED, requestId);
                return result;
            }

            // No need to check every request twice. If this request was permitted by a certificate manager, we are fine with it
            if (bNewRequest == 0)
                return result;

            // At this point, the certificate is completely constructed and ready to be issued, if we allow it

            #region Additional Checks

            var templateOid = certServerPolicy.GetStringCertificatePropertyOrDefault("CertificateTemplate");

            // Deny the request if no template info can be found (this should never happen though)
            if (templateOid == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO, requestId);

                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            var templateInfo = _templateInfo.GetTemplate(templateOid);

            // Deny the request if no template info can be found in local cache (this should never happen though)
            if (templateInfo == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO, requestId);

                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            // Don't bother with templates that are configured to build subject from AD
            if (!templateInfo.EnrolleeSuppliesSubject)
            {
                _logger.Log(Events.POLICY_NOT_APPLICABLE, templateInfo.Name, requestId);

                return result;
            }

            // Finally... here we will do our additional checks
            var policyFile = Path.Combine(_policyDirectory, $"{templateInfo.Name}.xml");

            // Issue the certificate of no policy is defined
            if (!File.Exists(policyFile))
            {
                _logger.Log(Events.POLICY_NOT_FOUND, templateInfo.Name, requestId, policyFile);

                return result;
            }

            var requestValidator = new CertificateRequestValidator();
            var requestPolicy = requestValidator.LoadFromFile(policyFile);

            // Deny the request if unable to parse policy file
            if (null == requestPolicy)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_POLICY, policyFile, requestId);

                return WinError.NTE_FAIL;
            }
            
            var request = certServerPolicy.GetBinaryRequestPropertyOrDefault("RawRequest");
            var requestType = (int) certServerPolicy.GetLongRequestPropertyOrDefault("RequestType") ^ CertCli.CR_IN_FULLRESPONSE;

            // Verify the Certificate request against policy
            var validationResult =
                requestValidator.VerifyRequest(Convert.ToBase64String(request), requestPolicy, requestType);

            // No reason to deny the request, let's issue the certificate
            if (validationResult.Success) return result;

            // Also issue the certificate when the request policy is set to AuditOnly
            if (validationResult.AuditOnly)
            {
                _logger.Log(Events.REQUEST_DENIED_AUDIT, requestId, templateInfo.Name,
                    string.Join("\n", validationResult.Description));

                return result;
            }

            // Deny the request if validation was not successful
            _logger.Log(Events.REQUEST_DENIED, requestId, templateInfo.Name,
                string.Join("\n", validationResult.Description));

            // Return the result code handed over by the RequestValidator class
            return validationResult.StatusCode;

            #endregion
        }

        public void ShutDown()
        {
            try
            {
                _windowsDefaultPolicyModule.GetType().InvokeMember(
                    "Shutdown",
                    BindingFlags.InvokeMethod,
                    null,
                    _windowsDefaultPolicyModule,
                    null
                );
            }
            catch (Exception ex)
            {
                _logger.Log(Events.PDEF_FAIL_SHUTDOWN, ex);

                throw;
            }
        }

        #endregion
    }
}