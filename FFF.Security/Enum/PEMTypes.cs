namespace FFF.Security
{
    /// <summary>
    /// Defines various types of PEM (Privacy Enhanced Mail) formats.
    /// PEM is a file format commonly used to store and transmit cryptographic keys,
    /// certificates, and other data.
    /// </summary>
    internal enum PEMTypes
    {
        /// <summary>
        /// Represents an unknown or uninitialized PEM type.
        /// Useful for default cases or error handling.
        /// </summary>
        Unknown = 0,

        // Grouping of X509 certificate related types
        PEM_X509_OLD,        // The old format of X509 certificate
        PEM_X509,           // Standard X509 certificate
        PEM_X509_PAIR,       // X509 key and certificate pair
        PEM_X509_TRUSTED,    // Trusted X509 certificate
        PEM_X509_REQ_OLD,     // The old format of X509 certificate request
        PEM_X509_REQ,        // X509 certificate request
        PEM_X509_CRL,        // X509 certificate revocation list (CRL)

        // Grouping of public/private key and related certificate types
        PEM_EVP_PKEY,        // Generic private key
        PEM_PUBLIC,         // Public key
        PEM_RSA,            // RSA private key
        PEM_RSA_PUBLIC,      // RSA public key
        PEM_DSA,            // DSA private key
        PEM_DSA_PUBLIC,      // DSA public key
        PEM_PKCS7,          // PKCS#7 cryptographic message syntax
        PEM_PKCS7_SIGNED,    // PKCS#7 signed data
        PEM_PKCS8,          // PKCS#8 private key information syntax
        PEM_PKCS8INF,       // PKCS#8 format private key (unencrypted)

        // Grouping of other miscellaneous PEM types
        PEM_DHPARAMS,       // Diffie-Hellman parameters
        PEM_SSL_SESSION,     // SSL session parameters
        PEM_DSAPARAMS,      // DSA parameters
        PEM_ECDSA_PUBLIC,    // ECDSA public key
        PEM_ECPARAMETERS,   // Elliptic curve parameters
        PEM_ECPRIVATEKEY,   // Elliptic curve private key
        PEM_CMS,            // Cryptographic Message Syntax
        PEM_SSH2_PUBLIC,      // Public key for SSH2
        UNKNOWN
    }
}
