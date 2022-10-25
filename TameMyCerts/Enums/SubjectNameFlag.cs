using System;

namespace TameMyCerts.Enums
{
    /// <summary>
    ///     Certificate Subject Name Flags from CertCa.h
    /// </summary>
    [Flags]
    public enum SubjectNameFlag : uint
    {
        /// <summary>
        ///     The enrolling application must supply the subject name.
        /// </summary>
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,

        /// <summary>
        ///     The enrolling application must supply the subjectAltName in request
        /// </summary>
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,

        /// <summary>
        ///     Subject name should be full DN
        /// </summary>
        CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,

        /// <summary>
        ///     Subject name should be the common name
        /// </summary>
        CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,

        /// <summary>
        ///     Subject name includes the e-mail name
        /// </summary>
        CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000,

        /// <summary>
        ///     Subject name includes the DNS name as the common name
        /// </summary>
        CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000,

        /// <summary>
        ///     Subject alt name includes DNS name
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000,

        /// <summary>
        ///     Subject alt name includes email name
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,

        /// <summary>
        ///     Subject alt name requires UPN
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000,

        /// <summary>
        ///     Subject alt name requires directory GUID
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,

        /// <summary>
        ///     Subject alt name requires SPN
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000,

        /// <summary>
        ///     Subject alt name requires Domain DNS name
        /// </summary>
        CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,

        /// <summary>
        ///     Subject name should be copied from the renewing certificate
        /// </summary>
        CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    }
}