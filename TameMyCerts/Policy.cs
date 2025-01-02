// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

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
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using CERTCLILib;
using CERTPOLICYLib;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

namespace TameMyCerts;

[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("TameMyCerts.Policy")]
[Guid("432413c6-2e86-4667-9697-c1e038877ef9")] // must be distinct from PolicyManage Class
public class Policy : ICertPolicy2
{
    private readonly string _appName;
    private readonly string _appVersion;
    private readonly CertificateContentValidator _ccValidator = new();
    private readonly CertificateRequestValidator _crValidator = new();
    private readonly DirectoryServiceValidator _dsValidator = new();
    private readonly FinalResultValidator _frValidator = new();
    private readonly RequestAttributeValidator _raValidator = new();
    private readonly CertificateTemplateCache _templateCache = new();
    private readonly YubikeyValidator _ykValidator = new();
    private CertificateAuthorityConfiguration _caConfig;
    private Logger _logger;
    private CertificateRequestPolicyCache _policyCache;
    private ICertPolicy2 _windowsDefaultPolicyModule;

    #region Constructor

    public Policy()
    {
        var assembly = Assembly.GetExecutingAssembly();

        _appName = ((AssemblyTitleAttribute)assembly.GetCustomAttribute(
            typeof(AssemblyTitleAttribute))).Title;

        _appVersion = ((AssemblyFileVersionAttribute)assembly.GetCustomAttribute(
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
        _caConfig = new CertificateAuthorityConfiguration(strConfig, _appName);
        _logger = new Logger(_appName, _caConfig.LogLevel);
        _policyCache = new CertificateRequestPolicyCache(_caConfig.PolicyDirectory);

        PreventModuleLoadOnStandaloneCa();
        InitializeWindowsDefaultPolicyModule(strConfig);
    }

    public int VerifyRequest(string strConfig, int context, int isNewRequest, int flags)
    {
        var serverPolicy = new CCertServerPolicy();
        serverPolicy.SetContext(context);

        var requestId = serverPolicy.GetLongRequestPropertyOrDefault("RequestId");
        int disposition;

        #region Hand the request over to the Windows Default policy module

        try
        {
            disposition = _windowsDefaultPolicyModule.VerifyRequest(strConfig, context, isNewRequest, flags);
        }
        catch (Exception ex)
        {
            _logger.Log(Events.PDEF_REQUEST_DENIED_MESSAGE, requestId, ex.Message);
            throw;
        }

        if (!(disposition == CertSrv.VR_PENDING || disposition == CertSrv.VR_INSTANT_OK))
        {
            _logger.Log(Events.PDEF_REQUEST_DENIED, requestId);
            return disposition;
        }

        #endregion

        // It seems that the Windows default module invalidates our data if we put it ahead of the call
        var dbRow = new CertificateDatabaseRow(serverPolicy);

        #region Fetch certificate template information

        var template = _templateCache.GetCertificateTemplate(dbRow.CertificateTemplate);

        if (template == null)
        {
            _logger.Log(Events.REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL, requestId);
            return WinError.CERTSRV_E_UNSUPPORTED_CERT_TYPE;
        }

        #endregion

        var result = new CertificateRequestValidationResult(dbRow);

        #region Process policy-independent validators

        result = _raValidator.VerifyRequest(result, dbRow, _caConfig);

        #endregion

        var cacheEntry = _policyCache.GetCertificateRequestPolicy(template.Name);

        if (cacheEntry == null)
        {
            if (_caConfig.TmcFlags.HasFlag(TmcFlag.TMC_DENY_IF_NO_POLICY))
            {
                _logger.Log(Events.REQUEST_DENIED_POLICY_NOT_FOUND, template.Name, requestId);
                return WinError.NTE_FAIL;
            }

            _logger.Log(Events.POLICY_NOT_FOUND, template.Name, requestId);
        }
        else
        {
            #region Load policy from cache

            var policy = cacheEntry.CertificateRequestPolicy;

            if (null == policy)
            {
                _logger.Log(Events.REQUEST_DENIED_NO_POLICY, requestId, template.Name,
                    cacheEntry.ErrorMessage);
                return WinError.NTE_FAIL;
            }

            #endregion

            #region Process policy-dependent validators

            result = _crValidator.VerifyRequest(result, policy, dbRow, template);

            result = _dsValidator.GetMappedActiveDirectoryObject(result, policy, dbRow, template, _caConfig,
                out var dsObject);
            result = _ykValidator.ExtractAttestion(result, policy, dbRow, out var ykObject);

            result = _dsValidator.VerifyRequest(result, policy, dsObject);
            result = _ykValidator.VerifyRequest(result, policy, ykObject, dbRow.RequestID);
            result = _ccValidator.VerifyRequest(result, policy, dbRow, dsObject, _caConfig, ykObject);
            result = _frValidator.VerifyRequest(result, policy, dbRow);

            #endregion

            #region Issue certificate if in audit mode

            if (policy.AuditOnly)
            {
                if (result.DeniedForIssuance)
                {
                    ETWLogger.Log.TMC_5_Analytical_Audit_only_Deny(requestId, template.Name,
                        string.Join("\n", result.Description));
                    _logger.Log(Events.REQUEST_DENIED_AUDIT, requestId, template.Name,
                        string.Join("\n", result.Description));
                }

                return disposition;
            }

            #endregion

            #region Modify certificate content, if changed by a validator

            result.DisabledCertificateExtensions.ForEach(oid =>
                serverPolicy.DisableCertificateExtension(oid));

            // TODO: There may be cases where the SAN extension must be made critical, how can we identify and accomplish this?
            result.CertificateExtensions.ToList().ForEach(keyValuePair =>
                serverPolicy.SetCertificateExtension(keyValuePair.Key, keyValuePair.Value));

            result.DisabledCertificateProperties.ForEach(name =>
                serverPolicy.DisableCertificateProperty(name));

            result.CertificateProperties.ToList().ForEach(keyValuePair =>
                serverPolicy.SetCertificateProperty(keyValuePair.Key, keyValuePair.Value));

            #endregion
        }

        #region Log warnings, if any

        if (result.Warnings.Count > 0)
        {
            _logger.Log(Events.REQUEST_CONTAINS_WARNINGS, requestId, template.Name,
                string.Join("\n", result.Warnings.Distinct().ToList()));
        }

        #endregion

        #region Modify certificate validity period, if changed by a validator

        // Modify certificate validity period (if changed) and issue certificate (or put in pending state)
        if (!result.DeniedForIssuance || isNewRequest == 0)
        {
            serverPolicy.SetCertificateProperty("NotBefore", result.NotBefore);
            serverPolicy.SetCertificateProperty("NotAfter", result.NotAfter);

            switch (disposition)
            {
                case CertSrv.VR_PENDING:
                    ETWLogger.Log.TMC_13_Success_Pending(requestId, template.Name);
                    _logger.Log(Events.SUCCESS_PENDING, requestId, template.Name);
                    break;
                case CertSrv.VR_INSTANT_OK:
                    ETWLogger.Log.TMC_12_Success_Issued(requestId, template.Name);
                    _logger.Log(Events.SUCCESS_ISSUED, requestId, template.Name);
                    break;
            }

            return disposition;
        }

        #endregion

        #region Deny request in any other case

        ETWLogger.Log.TMC_6_Deny_Issuing_Request(requestId, template.Name,
            string.Join("\n", result.Description.Distinct().ToList()));
        _logger.Log(Events.REQUEST_DENIED, requestId, template.Name,
            string.Join("\n", result.Description.Distinct().ToList()));

        // Seems that lower error codes must be thrown as exception
        if (result.StatusCode is > CertSrv.VR_INSTANT_BAD and <= WinError.ERROR_INVALID_TIME)
        {
            throw new COMException(string.Empty, result.StatusCode);
        }

        return result.StatusCode;

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
            ETWLogger.Log.TMC_4_PolicyModule_Default_Shutdown_Failed(ex.ToString());
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
                (ICertPolicy2)Activator.CreateInstance(
                    Type.GetTypeFromProgID("CertificateAuthority_MicrosoftDefault.Policy", true));

            _windowsDefaultPolicyModule.Initialize(strConfig);

            ETWLogger.Log.TMC_1_PolicyModule_Success_Initiated(_appName, _appVersion);
            _logger.Log(Events.PDEF_SUCCESS_INIT, _appName, _appVersion);
        }
        catch (Exception ex)
        {
            ETWLogger.Log.TMC_2_PolicyModule_Failed_Initiated(ex.ToString());
            _logger.Log(Events.PDEF_FAIL_INIT, ex);
            Marshal.ReleaseComObject(_windowsDefaultPolicyModule);
            throw;
        }
    }

    #endregion
}