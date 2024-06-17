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
using System.Collections.Generic;
using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using CERTENROLLLib;
using TameMyCerts.Models;

namespace TameMyCerts.X509
{
    public class X509CertificateExtensionSubjectAlternativeName : X509CertificateExtension
    {
        /// <summary>
        ///     An indicator if the extension was modified. If not, it returns the un-changed RawData.
        /// </summary>
        private bool _modified;

        public X509CertificateExtensionSubjectAlternativeName()
        {
        }

        public X509CertificateExtensionSubjectAlternativeName(byte[] rawData)
        {
            InitializeDecode(Convert.ToBase64String(rawData));
        }

        public X509CertificateExtensionSubjectAlternativeName(string rawData)
        {
            InitializeDecode(rawData);
        }

        public List<KeyValuePair<string, string>> AlternativeNames { get; } =
            new List<KeyValuePair<string, string>>();

        private void InitializeDecode(string rawData)
        {
            // There are rare cases when the CA database contains an empty SAN extension
            if (rawData.Equals(string.Empty))
            {
                return;
            }

            var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

            try
            {
                extensionAlternativeNames.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);

                RawData = Convert.FromBase64String(extensionAlternativeNames
                    .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64).Replace(Environment.NewLine, string.Empty));

                foreach (IAlternativeName san in extensionAlternativeNames.AlternativeNames)
                {
                    switch (san.Type)
                    {
                        case AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME:

                            AlternativeNames.Add(
                                new KeyValuePair<string, string>(SanTypes.DnsName, san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME:

                            AlternativeNames.Add(
                                new KeyValuePair<string, string>(SanTypes.Rfc822Name, san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_URL:

                            AlternativeNames.Add(
                                new KeyValuePair<string, string>(SanTypes.UniformResourceIdentifier,
                                    san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME:

                            AlternativeNames.Add(
                                new KeyValuePair<string, string>(SanTypes.UserPrincipalName,
                                    san.strValue));
                            break;

                        case AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS:

                            AlternativeNames.Add(new KeyValuePair<string, string>(SanTypes.IpAddress,
                                new IPAddress(
                                        Convert.FromBase64String(san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)))
                                    .ToString()));
                            break;

                        // Others are not supported and will be discarded without further notice, should the extension be modified.
                    }

                    Marshal.ReleaseComObject(san);
                }
            }
            catch
            {
                Marshal.ReleaseComObject(extensionAlternativeNames);
                throw;
            }

            Marshal.ReleaseComObject(extensionAlternativeNames);
        }

        public void InitializeEncode()
        {
            // This ensures we return the unmodified original RawData if the Extension was not modified.
            if (!_modified)
            {
                return;
            }

            if (AlternativeNames.Count == 0)
            {
                RawData = Array.Empty<byte>();
                return;
            }

            var alternativeNames = new CAlternativeNames();

            foreach (var keyValuePair in AlternativeNames)
            {
                var alternativeName = new CAlternativeName();

                switch (keyValuePair.Key)
                {
                    case SanTypes.DnsName:
                        alternativeName.InitializeFromString(
                            AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                            keyValuePair.Value);
                        break;

                    case SanTypes.IpAddress:
                        alternativeName.InitializeFromRawData(
                            AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS,
                            EncodingType.XCN_CRYPT_STRING_BASE64,
                            Convert.ToBase64String(IPAddress.Parse(keyValuePair.Value).GetAddressBytes()));
                        break;

                    case SanTypes.UserPrincipalName:
                        alternativeName.InitializeFromString(
                            AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME,
                            keyValuePair.Value);
                        break;

                    case SanTypes.Rfc822Name:
                        alternativeName.InitializeFromString(
                            AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME,
                            keyValuePair.Value);
                        break;

                    case SanTypes.UniformResourceIdentifier:
                        alternativeName.InitializeFromString(
                            AlternativeNameType.XCN_CERT_ALT_NAME_URL,
                            keyValuePair.Value);
                        break;
                }

                alternativeNames.Add(alternativeName);
                Marshal.ReleaseComObject(alternativeName);
            }

            var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

            extensionAlternativeNames.InitializeEncode(alternativeNames);
            Marshal.ReleaseComObject(alternativeNames);

            RawData = Convert.FromBase64String(extensionAlternativeNames
                .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64).Replace(Environment.NewLine, string.Empty));

            Marshal.ReleaseComObject(extensionAlternativeNames);
        }

        public void AddDnsName(string value)
        {
            AddAlternativeName(SanTypes.DnsName, value);
        }

        public void AddIpAddress(IPAddress value)
        {
            AddAlternativeName(SanTypes.IpAddress, value.ToString());
        }

        public void AddUserPrincipalName(string value)
        {
            AddAlternativeName(SanTypes.UserPrincipalName, value);
        }

        public void AddEmailAddress(string value)
        {
            AddAlternativeName(SanTypes.Rfc822Name, value);
        }

        public void AddEmailAddress(MailAddress value)
        {
            AddAlternativeName(SanTypes.Rfc822Name, value.ToString());
        }

        public void AddUniformResourceIdentifier(string value)
        {
            AddAlternativeName(SanTypes.UniformResourceIdentifier, value);
        }

        public void AddUniformResourceIdentifier(Uri value)
        {
            AddAlternativeName(SanTypes.UniformResourceIdentifier, value.ToString());
        }

        public void RemoveDnsName(string value)
        {
            RemoveAlternativeName(SanTypes.DnsName, value);
        }

        public void RemoveIpAddress(IPAddress value)
        {
            RemoveAlternativeName(SanTypes.IpAddress, value.ToString());
        }

        public void RemoveUserPrincipalName(string value)
        {
            RemoveAlternativeName(SanTypes.UserPrincipalName, value);
        }

        public void RemoveEmailAddress(string value)
        {
            RemoveAlternativeName(SanTypes.Rfc822Name, value);
        }

        public void RemoveEmailAddress(MailAddress value)
        {
            RemoveAlternativeName(SanTypes.Rfc822Name, value.ToString());
        }

        public void RemoveUniformResourceIdentifier(string value)
        {
            RemoveAlternativeName(SanTypes.UniformResourceIdentifier, value);
        }

        public void RemoveUniformResourceIdentifier(Uri value)
        {
            RemoveAlternativeName(SanTypes.UniformResourceIdentifier, value.ToString());
        }

        /// <summary>
        ///     Essentially the same as TryAddAlternativeName but without caring for the result.
        /// </summary>
        /// <param name="type"></param>
        /// <param name="value"></param>
        public void AddAlternativeName(string type, string value, bool throwOnError = false)
        {
            if (!TryAddAlternativeName(type, value) && throwOnError)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.San_unable_to_add, type, value));
            }
        }

        public bool TryAddAlternativeName(string type, string value)
        {
            if (ContainsAlternativeName(type, value))
            {
                return true;
            }

            switch (type)
            {
                case SanTypes.DnsName:

                    if (Uri.CheckHostName(value) != UriHostNameType.Dns)
                    {
                        return false;
                    }

                    break;

                case SanTypes.Rfc822Name:
                case SanTypes.UserPrincipalName:

                    try
                    {
                        _ = new MailAddress(value);
                    }
                    catch
                    {
                        return false;
                    }

                    break;

                case SanTypes.IpAddress:

                    if (!IPAddress.TryParse(value, out _))
                    {
                        return false;
                    }

                    break;

                case SanTypes.UniformResourceIdentifier:

                    if (!Uri.TryCreate(value, UriKind.Absolute, out _))
                    {
                        return false;
                    }

                    break;

                default: return false;
            }

            AlternativeNames.Add(new KeyValuePair<string, string>(type, value));
            _modified = true;

            return true;
        }

        public bool ContainsAlternativeName(string type, string value)
        {
            return AlternativeNames.Contains(new KeyValuePair<string, string>(type, value));
        }

        public void RemoveAlternativeName(string type, string value)
        {
            if (!ContainsAlternativeName(type, value))
            {
                return;
            }

            AlternativeNames.Remove(new KeyValuePair<string, string>(type, value));
            _modified = true;
        }
    }
}