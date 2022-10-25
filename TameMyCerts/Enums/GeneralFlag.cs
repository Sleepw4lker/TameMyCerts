namespace TameMyCerts.Enums
{
    /// <summary>
    ///     General flags from CertCa.h
    /// </summary>
    public enum GeneralFlag : uint
    {
        /// <summary>
        ///     This is a machine cert type
        /// </summary>
        CT_FLAG_MACHINE_TYPE = 0x00000040,

        /// <summary>
        ///     This is a CA	cert type
        /// </summary>
        CT_FLAG_IS_CA = 0x00000080,

        /// <summary>
        ///     This is a cross CA cert type
        /// </summary>
        CT_FLAG_IS_CROSS_CA = 0x00000800,

        /// <summary>
        ///     Tells the CA that this certificate should not be persisted in // the database if the CA is configured to do so.
        /// </summary>
        CT_FLAG_DONOTPERSISTINDB = 0x00001000,

        /// <summary>
        ///     The type is a default cert type (cannot be set).  This flag will be set on all V1 templates. The templates can not
        ///     be edited or deleted.
        /// </summary>
        CT_FLAG_IS_DEFAULT = 0x00010000,

        /// <summary>
        ///     The type has been modified, if it is default (cannot be set)
        /// </summary>
        CT_FLAG_IS_MODIFIED = 0x00020000,

        /// <summary>
        ///     settable flags for general flags
        /// </summary>
        CT_MASK_SETTABLE_FLAGS = 0x0000ffff
    }
}