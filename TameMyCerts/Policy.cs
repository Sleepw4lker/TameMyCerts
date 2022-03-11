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
using System.Globalization;
using System.IO;
using System.Linq;
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
        private const string CONFIG_ROOT =
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration";

        private const string DATETIME_RFC2616 = "ddd, d MMM yyyy HH:mm:ss 'GMT'";

        private readonly string _appName;
        private readonly string _appVersion;
        private readonly CertificateRequestValidator _requestValidator = new CertificateRequestValidator();
        private readonly CertificateTemplateInfo _templateInfo = new CertificateTemplateInfo();
        private int _editFlags;
        private Logger _logger;
        private string _policyDirectory;
        private dynamic _windowsDefaultPolicyModule;

        #region Constructor

        public Policy()
        {
            var assembly = Assembly.GetExecutingAssembly();

            _appName = ((AssemblyTitleAttribute) assembly.GetCustomAttribute(
                typeof(AssemblyTitleAttribute))).Title;

            _appVersion = ((AssemblyFileVersionAttribute) assembly.GetCustomAttribute(
                typeof(AssemblyFileVersionAttribute))).Version;
        }

        #endregion

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
            InitializeLogger(strConfig);
            PreventModuleLoadOnStandaloneCa(strConfig);
            LoadSettingsFromRegistry(strConfig);
            InitializeWindowsDefaultPolicyModule(strConfig);
        }

        public int VerifyRequest(string strConfig, int context, int bNewRequest, int flags)
        {
            #region Initialization

            int result;

            var certServerPolicy = new CCertServerPolicy();

            certServerPolicy.SetContext(context);

            var requestId = certServerPolicy.GetLongRequestPropertyOrDefault("RequestId");

            #endregion

            #region Hand the request over to the Windows Default policy module

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
                // In some cases, the reason to deny a certificate comes in form of an exception (e.g. ERROR_INVALID_TIME), we return these here
                if (ex.InnerException is COMException)
                {
                    throw ex.InnerException;
                }

                // Only for the case something went wrong with calling the Windows Default policy module
                _logger.Log(Events.PDEF_FAIL_VERIFY, requestId, ex);
                return CertSrv.VR_INSTANT_BAD;
            }

            // We don't question if the default policy module decided to deny the request
            if (!(result == CertSrv.VR_PENDING || result == CertSrv.VR_INSTANT_OK))
            {
                _logger.Log(Events.PDEF_REQUEST_DENIED, requestId);
                return result;
            }

            // No need to check every request twice. If this request was permitted by a certificate manager, we are fine with it
            if (bNewRequest == 0)
            {
                return result;
            }

            // At this point, the certificate is completely constructed and ready to be issued, if we allow it

            #endregion

            #region Fetch request attributes

            var requestAttributeList = certServerPolicy.GetRequestAttributeList();

            #endregion

            #region Process insecure flag/attribute combinations

            // Deny requests containing the "san" request attribute
            if ((_editFlags & CertSrv.EDITF_ATTRIBUTESUBJECTALTNAME2) == CertSrv.EDITF_ATTRIBUTESUBJECTALTNAME2 &&
                requestAttributeList.Any(x => x.Key.Equals("san", StringComparison.InvariantCultureIgnoreCase)))
            {
                _logger.Log(Events.REQUEST_DENIED_INSECURE_FLAGS, requestId);
                return WinError.NTE_FAIL;
            }

            #endregion

            #region Process custom StartDate attribute

            // Set custom start date if requested and permitted
            if ((_editFlags & CertSrv.EDITF_ATTRIBUTEENDDATE) == CertSrv.EDITF_ATTRIBUTEENDDATE)
            {
                if (requestAttributeList.Any(
                        x => x.Key.Equals("StartDate", StringComparison.InvariantCultureIgnoreCase)))
                {
                    if (DateTimeOffset.TryParseExact(
                            requestAttributeList.FirstOrDefault(x =>
                                    x.Key.Equals("StartDate", StringComparison.InvariantCultureIgnoreCase))
                                .Value,
                            DATETIME_RFC2616, CultureInfo.InvariantCulture.DateTimeFormat,
                            DateTimeStyles.AssumeUniversal, out var requestedStartDate))
                    {
                        var notAfter = certServerPolicy.GetDateCertificatePropertyOrDefault("NotAfter");
                        if (requestedStartDate >= DateTimeOffset.Now && requestedStartDate <= notAfter)
                        {
                            certServerPolicy.SetCertificateProperty("NotBefore", CertSrv.PROPTYPE_DATE,
                                requestedStartDate.UtcDateTime);
                        }
                        else
                        {
                            // same behavior as Windows Default policy module with an invalid ExpirationDate
                            throw new COMException(string.Empty, WinError.ERROR_INVALID_TIME);
                        }
                    }
                }
            }

            #endregion

            #region Fetch certificate template information

            var templateOid = certServerPolicy.GetStringCertificatePropertyOrDefault("CertificateTemplate");

            if (templateOid == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO, requestId);
                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            var templateInfo = _templateInfo.GetTemplate(templateOid);

            if (templateInfo == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO, requestId);
                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            #endregion

            #region Process request policies

            var policyFile = Path.Combine(_policyDirectory, $"{templateInfo.Name}.xml");

            // Issue the certificate of no policy is defined
            if (!File.Exists(policyFile))
            {
                _logger.Log(Events.POLICY_NOT_FOUND, templateInfo.Name, requestId, policyFile);
                return result;
            }

            var requestPolicy = CertificateRequestPolicy.LoadFromFile(policyFile);

            // Deny the request if unable to parse policy file
            if (null == requestPolicy)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_POLICY, policyFile, requestId);
                return WinError.NTE_FAIL;
            }

            var request = certServerPolicy.GetBinaryRequestPropertyOrDefault("RawRequest");
            var requestType = certServerPolicy.GetLongRequestPropertyOrDefault("RequestType") ^
                              CertCli.CR_IN_FULLRESPONSE;

            // Verify the Certificate request against policy
            var validationResult =
                _requestValidator.VerifyRequest(Convert.ToBase64String(request), requestPolicy, templateInfo,
                    requestType,
                    requestAttributeList);

            // No reason to deny the request, let's issue the certificate
            if (validationResult.Success)
            {
                return result;
            }

            // Also issue the certificate when the request policy is set to AuditOnly
            if (validationResult.AuditOnly)
            {
                _logger.Log(Events.REQUEST_DENIED_AUDIT, requestId, templateInfo.Name,
                    string.Join("\n", validationResult.Description));
                return result;
            }

            // Deny the request in any other case (validation was not successful)
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

        #region Helper Methods

        private void InitializeLogger(string strConfig)
        {
            var logLevel = (int) Registry.GetValue(
                $"{CONFIG_ROOT}\\{strConfig}",
                "LogLevel",
                CertSrv.CERTLOG_WARNING
            );

            _logger = new Logger(_appName, logLevel);
        }

        private void PreventModuleLoadOnStandaloneCa(string strConfig)
        {
            var caType = (int) Registry.GetValue(
                $"{CONFIG_ROOT}\\{strConfig}",
                "CAType",
                CertSrv.ENUM_STANDALONE_ROOTCA
            );

            if (!(caType == CertSrv.ENUM_ENTERPRISE_ROOTCA || caType == CertSrv.ENUM_ENTERPRISE_SUBCA))
            {
                _logger.Log(Events.MODULE_NOT_SUPPORTED, _appName);
                throw new NotSupportedException();
            }
        }

        private void LoadSettingsFromRegistry(string strConfig)
        {
            var moduleRoot = $"{CONFIG_ROOT}\\{strConfig}\\PolicyModules\\{_appName}.Policy";

            _policyDirectory = (string) Registry.GetValue(moduleRoot, "PolicyDirectory", Path.GetTempPath());
            _editFlags = (int) Registry.GetValue(moduleRoot, "EditFlags", 0);
        }

        private void InitializeWindowsDefaultPolicyModule(string strConfig)
        {
            const string windowsDefaultPolicyModuleGuid = "3B6654D0-C2C8-11D2-B313-00C04F79DC72";

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
                throw;
            }
        }

        #endregion
    }
}