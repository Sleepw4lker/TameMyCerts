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
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using CERTCLILib;
using CERTPOLICYLib;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

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
        private readonly RequestAttributeValidator _attributeValidator = new RequestAttributeValidator();
        private readonly DirectoryServiceValidator _directoryServicesValidator = new DirectoryServiceValidator();
        private readonly CertificateRequestValidator _requestValidator = new CertificateRequestValidator();
        private readonly CertificateTemplateInfo _templateInfo = new CertificateTemplateInfo();
        private CertificationAuthorityConfiguration _caConfig;
        private Logger _logger;
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
            _caConfig = new CertificationAuthorityConfiguration(strConfig, _appName);
            _logger = new Logger(_appName, _caConfig.LogLevel);
            PreventModuleLoadOnStandaloneCa();
            InitializeWindowsDefaultPolicyModule(strConfig);
        }

        public int VerifyRequest(string strConfig, int context, int bNewRequest, int flags)
        {
            #region Initialization

            var serverPolicy = new CCertServerPolicy();
            serverPolicy.SetContext(context);

            var requestId = serverPolicy.GetLongRequestPropertyOrDefault("RequestId");

            #endregion

            #region Hand the request over to the Windows Default policy module

            int result;

            try
            {
                result = _windowsDefaultPolicyModule.VerifyRequest(strConfig, context, bNewRequest, flags);
            }
            catch (Exception ex)
            {
                _logger.Log(Events.PDEF_REQUEST_DENIED_MESSAGE, requestId, ex.Message);
                throw;
            }

            if (!(result == CertSrv.VR_PENDING || result == CertSrv.VR_INSTANT_OK))
            {
                _logger.Log(Events.PDEF_REQUEST_DENIED, requestId);
                return result;
            }

            #endregion

            #region Fetch certificate template information

            var templateOid = serverPolicy.GetStringCertificatePropertyOrDefault("CertificateTemplate");

            if (templateOid == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO, requestId);
                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            var certificateTemplate = _templateInfo.GetTemplate(templateOid);

            if (certificateTemplate == null)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL, requestId);
                return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
            }

            #endregion

            var validationResult = new CertificateRequestValidationResult
            {
                NotBefore = serverPolicy.GetDateCertificatePropertyOrDefault("NotBefore"),
                NotAfter = serverPolicy.GetDateCertificatePropertyOrDefault("NotAfter"),
                RequestAttributes = serverPolicy.GetRequestAttributes(),
                CertificateExtensions = serverPolicy.GetCertificateExtensions(),
                SubjectRelativeDistinguishedNames = serverPolicy.GetSubjectRelativeDistinguishedNames()
            };

            #region Process request policies

            var policyFile = Path.Combine(_caConfig.PolicyDirectory, $"{certificateTemplate.Name}.xml");

            if (!File.Exists(policyFile))
            {
                _logger.Log(Events.POLICY_NOT_FOUND, certificateTemplate.Name, requestId, policyFile);
                validationResult.ApplyPolicy = false;
            }

            // This must run whether a policy is configured or not (and also the date/time manipulation logic below)
            validationResult = _attributeValidator.VerifyRequest(validationResult, _caConfig);

            if (validationResult.ApplyPolicy)
            {
                var requestPolicy = CertificateRequestPolicy.LoadFromFile(policyFile);

                if (null == requestPolicy)
                {
                    _logger.Log(Events.REQUEST_DENIED_NO_POLICY, policyFile, requestId);
                    return WinError.NTE_FAIL;
                }

                if (!validationResult.DeniedForIssuance)
                {
                    var request = serverPolicy.GetBinaryRequestPropertyOrDefault("RawRequest");
                    var requestType = serverPolicy.GetLongRequestPropertyOrDefault("RequestType") ^
                                      CertCli.CR_IN_FULLRESPONSE;

                    validationResult = _requestValidator.VerifyRequest(
                        validationResult, requestPolicy, certificateTemplate, request, requestType);
                }

                if (!validationResult.DeniedForIssuance && null != requestPolicy.DirectoryServicesMapping)
                {
                    if (!certificateTemplate.EnrolleeSuppliesSubject)
                    {
                        var upn = serverPolicy.GetStringCertificatePropertyOrDefault("UPN");
                        validationResult.Identities.Add(certificateTemplate.UserScope
                            ? new KeyValuePair<string, string>("userPrincipalName", upn)
                            : new KeyValuePair<string, string>("dNSName", upn.Replace("$@", ".")));
                    }

                    validationResult = _directoryServicesValidator.VerifyRequest(
                        validationResult, requestPolicy, certificateTemplate);
                }

                #endregion

                #region Issue certificate if in audit mode

                if (validationResult.AuditOnly)
                {
                    if (validationResult.DeniedForIssuance)
                    {
                        _logger.Log(Events.REQUEST_DENIED_AUDIT, requestId, certificateTemplate.Name,
                            string.Join("\n", validationResult.Description));
                    }

                    return result;
                }

                #endregion

                #region Modify certificate content

                validationResult.DisabledExtensions.ForEach(x => serverPolicy.DisableCertificateExtension(x));
                validationResult.Extensions.ToList().ForEach(x => serverPolicy.SetCertificateExtension(x.Key, x.Value));

                validationResult.DisabledProperties.ForEach(x => serverPolicy.DisableCertificateProperty(x));
                validationResult.Properties.ForEach(x => serverPolicy.SetCertificateProperty(x.Key, x.Value));

                #endregion
            }

            serverPolicy.SetCertificateProperty("NotBefore", validationResult.NotBefore);
            serverPolicy.SetCertificateProperty("NotAfter", validationResult.NotAfter);

            #region Issue certificate (or put in pending state)

            if (!validationResult.DeniedForIssuance || bNewRequest == 0)
            {
                return result;
            }

            #endregion

            #region Deny request in any other case

            _logger.Log(Events.REQUEST_DENIED, requestId, certificateTemplate.Name,
                string.Join("\n", validationResult.Description));

            // Seems that lower error codes must be thrown as exception
            if (validationResult.StatusCode > CertSrv.VR_INSTANT_BAD &&
                validationResult.StatusCode <= WinError.ERROR_INVALID_TIME)
            {
                throw new COMException(string.Empty, validationResult.StatusCode);
            }

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

        private void PreventModuleLoadOnStandaloneCa()
        {
            if (_caConfig.IsSupportedCaType)
            {
                return;
            }

            _logger.Log(Events.MODULE_NOT_SUPPORTED, _appName);
            throw new NotSupportedException();
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