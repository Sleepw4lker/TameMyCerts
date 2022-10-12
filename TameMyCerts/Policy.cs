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

using System;
using System.Collections.Generic;
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
        private readonly DirectoryServicesValidator _directoryServicesValidator = new DirectoryServicesValidator();
        private readonly CertificateRequestValidator _requestValidator = new CertificateRequestValidator();
        private readonly CertificateTemplateInfo _templateInfo = new CertificateTemplateInfo();
        private int _editFlags;
        private Logger _logger;
        private string _policyDirectory;
        private ICertPolicy2 _windowsDefaultPolicyModule;

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
                result = _windowsDefaultPolicyModule.VerifyRequest(strConfig, context, bNewRequest, flags);
            }
            catch (Exception ex)
            {
                // In some (but not all) cases, the reason to deny a certificate comes in form of an exception
                // e.g. when "ExpirationDate" Argument cannot be parsed by the default policy module
                _logger.Log(Events.PDEF_REQUEST_DENIED_MESSAGE, requestId, ex.Message);
                throw;
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
            if ((_editFlags & CertSrv.EDITF_ATTRIBUTEENDDATE) == CertSrv.EDITF_ATTRIBUTEENDDATE &&
                requestAttributeList.TryGetValue("StartDate", out var startDate))
            {
                if (DateTimeOffset.TryParseExact(startDate, DATETIME_RFC2616,
                        CultureInfo.InvariantCulture.DateTimeFormat,
                        DateTimeStyles.AssumeUniversal, out var requestedStartDate))
                {
                    if (requestedStartDate >= DateTimeOffset.Now && requestedStartDate <=
                        certServerPolicy.GetDateCertificatePropertyOrDefault("NotAfter"))
                    {
                        _logger.Log(Events.STARTDATE_SET, requestId, requestedStartDate.UtcDateTime);

                        certServerPolicy.SetCertificateProperty("NotBefore", requestedStartDate.UtcDateTime);
                    }
                    else
                    {
                        _logger.Log(Events.STARTDATE_INVALID, requestId, requestedStartDate.UtcDateTime);

                        // same behavior as Windows Default policy module with an invalid ExpirationDate
                        throw new COMException(string.Empty, WinError.ERROR_INVALID_TIME);
                    }
                }
                else
                {
                    _logger.Log(Events.ATTRIB_ERR_PARSE, "StartDate", requestId, startDate);

                    // same behavior as Windows Default policy module with an invalid ExpirationDate
                    throw new ArgumentException();
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
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL, requestId);
                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            #endregion

            #region Process request policies

            var policyFile = Path.Combine(_policyDirectory, $"{templateInfo.Name}.xml");

            // Issue the certificate of no policy is defined, we assume this is desired behavior
            if (!File.Exists(policyFile))
            {
                _logger.Log(Events.POLICY_NOT_FOUND, templateInfo.Name, requestId, policyFile);
                return result;
            }

            var requestPolicy = CertificateRequestPolicy.LoadFromFile(policyFile);

            // Deny the request if unable to parse policy file, as a safety measure
            if (null == requestPolicy)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_POLICY, policyFile, requestId);
                return WinError.NTE_FAIL;
            }

            var request = certServerPolicy.GetBinaryRequestPropertyOrDefault("RawRequest");
            var requestType = certServerPolicy.GetLongRequestPropertyOrDefault("RequestType") ^
                              CertCli.CR_IN_FULLRESPONSE;

            // Verify the Certificate request against policy
            var validationResult = _requestValidator.VerifyRequest(Convert.ToBase64String(request), requestPolicy,
                templateInfo, requestType, requestAttributeList);

            // Verify against directory if a policy is present
            if (!validationResult.DeniedForIssuance && null != requestPolicy.DirectoryServicesMapping)
            {
                if (!templateInfo.EnrolleeSuppliesSubject && templateInfo.UserScope)
                {
                    // This is always present on online templates
                    validationResult.Identities.Add(new KeyValuePair<string, string>("userPrincipalName",
                        certServerPolicy.GetStringCertificatePropertyOrDefault("UPN")));
                }

                if (templateInfo.EnrolleeSuppliesSubject || templateInfo.UserScope)
                {
                    validationResult = _directoryServicesValidator.VerifyRequest(requestPolicy, validationResult);
                }
            }

            // No reason to deny the request, let's issue the certificate
            if (!validationResult.DeniedForIssuance)
            {
                // Add Subject Relative Distinguished Names, if any
                foreach (var property in validationResult.Properties)
                {
                    certServerPolicy.SetCertificateProperty(property.Key, property.Value);
                }

                // Add certificate extensions, if any
                foreach (var extension in validationResult.Extensions)
                {
                    certServerPolicy.SetCertificateExtension(extension.Key, extension.Value);
                }

                if (validationResult.NotAfter == DateTimeOffset.MinValue || validationResult.NotAfter >
                    certServerPolicy.GetDateCertificatePropertyOrDefault("NotAfter"))
                {
                    return result;
                }

                // Shorten the expiration date, if configured by policy

                certServerPolicy.SetCertificateProperty("NotAfter", validationResult.NotAfter.UtcDateTime);

                _logger.Log(Events.VALIDITY_REDUCED, requestId, templateInfo.Name,
                    validationResult.NotAfter.UtcDateTime);

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
                _windowsDefaultPolicyModule.ShutDown();
            }
            catch (Exception ex)
            {
                _logger.Log(Events.PDEF_FAIL_SHUTDOWN, ex);
                throw;
            }
            finally
            {
                Marshal.ReleaseComObject(_windowsDefaultPolicyModule);
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

            if (caType == CertSrv.ENUM_ENTERPRISE_ROOTCA || caType == CertSrv.ENUM_ENTERPRISE_SUBCA)
            {
                return;
            }

            _logger.Log(Events.MODULE_NOT_SUPPORTED, _appName);
            throw new NotSupportedException();
        }

        private void LoadSettingsFromRegistry(string strConfig)
        {
            var policyModulesRoot = $"{CONFIG_ROOT}\\{strConfig}\\PolicyModules";

            var activePolicyModuleName = (string) Registry.GetValue(policyModulesRoot, "Active", _appName);
            var activePolicyModuleRoot = $"{policyModulesRoot}\\{activePolicyModuleName}";

            _policyDirectory =
                (string) Registry.GetValue(activePolicyModuleRoot, "PolicyDirectory", Path.GetTempPath());
            _editFlags = (int) Registry.GetValue(activePolicyModuleRoot, "EditFlags", 0);
        }

        private void InitializeWindowsDefaultPolicyModule(string strConfig)
        {
            try
            {
                _windowsDefaultPolicyModule =
                    (ICertPolicy2) Activator.CreateInstance(
                        Type.GetTypeFromProgID("CertificateAuthority_MicrosoftDefault.Policy", true));

                _windowsDefaultPolicyModule.Initialize(strConfig);

                _logger.Log(Events.PDEF_SUCCESS_INIT, _appName, _appVersion);
            }
            catch (Exception ex)
            {
                _logger.Log(Events.PDEF_FAIL_INIT, ex);
                Marshal.ReleaseComObject(_windowsDefaultPolicyModule);
                throw;
            }
        }

        #endregion
    }
}