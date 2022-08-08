using System;
using System.DirectoryServices;
using System.Linq;

namespace TameMyCerts
{
    public class DirectoryServicesValidator
    {
        private readonly string _forestRootDomain;

        public DirectoryServicesValidator()
        {
            _forestRootDomain = GetForestRootDomain();
        }

        private static string GetForestRootDomain()
        {
            try
            {
                var directoryEntry = new DirectoryEntry("LDAP://RootDSE");
                return directoryEntry.Properties["rootDomainNamingContext"][0].ToString();
            }
            catch
            {
                return null;
            }
        }

        public CertificateRequestValidationResult VerifyRequest(CertificateRequestPolicy certificateRequestPolicy,
            CertificateRequestValidationResult result)
        {
            var dsMapping = certificateRequestPolicy.DirectoryServicesMapping;

            string[] validDirectoryAttributes = {"cn", "name", "sAMAccountName", "userPrincipalName", "dNSHostName"};
            string[] validObjectTypes = {"computer", "user"};

            if (!validDirectoryAttributes.Any(s =>
                    s.IndexOf(dsMapping.DirectoryServicesAttribute, StringComparison.CurrentCultureIgnoreCase) > -1))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Invalid_Directory_Attribute,
                    dsMapping.DirectoryServicesAttribute));
                return result;
            }

            if (!validObjectTypes.Any(s =>
                    s.IndexOf(dsMapping.ObjectCategory, StringComparison.CurrentCultureIgnoreCase) > -1))
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Invalid_Object_Category,
                    dsMapping.ObjectCategory));
                return result;
            }

            var identity = result.Identities.FirstOrDefault(x =>
                x.Key.Equals(dsMapping.CertificateAttribute)).Value;

            if (string.IsNullOrEmpty(identity))
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.DirVal_No_Cert_Identity,
                    dsMapping.CertificateAttribute));
                return result;
            }

            var searchRoot = string.IsNullOrEmpty(dsMapping.SearchRoot)
                ? new DirectoryEntry($"GC://{_forestRootDomain}")
                : new DirectoryEntry($"LDAP://{dsMapping.SearchRoot}");

            var directorySearcher = new DirectorySearcher(searchRoot)
            {
                SearchRoot = searchRoot,
                Filter =
                    $"(&({dsMapping.DirectoryServicesAttribute}={identity})(objectCategory={dsMapping.ObjectCategory}))",
                PropertiesToLoad = {"memberOf", "objectSid", "userAccountControl"},
                PageSize = 2
            };

            SearchResultCollection searchResults;
            try
            {
                searchResults = directorySearcher.FindAll();
            }
            catch (Exception ex)
            {
                result.SetFailureStatus(string.Format(LocalizedStrings.DirVal_Query_Failed, ex.Message));
                return result;
            }

            if (searchResults.Count != 1)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.DirVal_Invalid_Result_Count,
                    dsMapping.ObjectCategory, dsMapping.DirectoryServicesAttribute, identity));
                return result;
            }

            if ((Convert.ToInt32(searchResults[0].Properties["userAccountControl"][0]) & 0x2) == 0x2)
            {
                result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                    LocalizedStrings.DirVal_Account_Disabled,
                    dsMapping.ObjectCategory, identity));
                return result;
            }

            if (dsMapping.AllowedSecurityGroups.Count > 0)
            {
                var matchFound = false;
                for (var index = 0; index < searchResults[0].Properties["memberOf"].Count; index++)
                {
                    var group = searchResults[0].Properties["memberOf"][index];
                    if (dsMapping.AllowedSecurityGroups.Any(x =>
                            x.Equals(group.ToString(), StringComparison.InvariantCultureIgnoreCase)))
                    {
                        matchFound = true;
                    }
                }

                if (!matchFound)
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Not_Allowed,
                        dsMapping.ObjectCategory, identity));
                }
            }

            #region process memberships of disallowed groups

            if (dsMapping.DisallowedSecurityGroups.Count <= 0)
            {
                return result;
            }

            for (var index = 0; index < searchResults[0].Properties["memberOf"].Count; index++)
            {
                var group = searchResults[0].Properties["memberOf"][index];
                if (dsMapping.DisallowedSecurityGroups.Any(x =>
                        x.Equals(group.ToString(), StringComparison.InvariantCultureIgnoreCase)))
                {
                    result.SetFailureStatus(WinError.CERTSRV_E_TEMPLATE_DENIED, string.Format(
                        LocalizedStrings.DirVal_Account_Groups_Disallowed,
                        dsMapping.ObjectCategory, identity, group));
                }
            }

            #endregion

            return result;
        }
    }
}