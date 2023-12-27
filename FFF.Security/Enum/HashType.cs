namespace FFF.Security
{
    /// <summary>
    /// Represents different types of hash algorithms.
    /// </summary>
    /// This enumeration is part of the FFF.Security namespace,
    /// which likely contains other security-related classes and enums.
    public enum HashType
    {
        // The following are members of the HashType enumeration,
        // each representing a different hash algorithm.

        HMAC = 1,         // HMAC (keyed-hash message authentication code)
        HMACMD5 = 2,      // HMAC using MD5 hash algorithm
        HMACSHA1 = 3,     // HMAC using SHA1 hash algorithm
        HMACSHA256 = 4,   // HMAC using SHA256 hash algorithm
        HMACSHA384 = 5,   // HMAC using SHA384 hash algorithm
        HMACSHA512 = 6,   // HMAC using SHA512 hash algorithm
        MACTripleDES = 7, // MAC (Message Authentication Code) using TripleDES
        MD5 = 8,          // MD5 hash algorithm
        RIPEMD160 = 9,    // RIPEMD-160 hash algorithm
        SHA1 = 10,        // SHA1 hash algorithm
        SHA256 = 11,      // SHA256 hash algorithm
        SHA384 = 12,      // SHA384 hash algorithm
        SHA512 = 13       // SHA512 hash algorithm

        // Explicitly assigning integer values to each member ensures that
        // the values remain constant even if more types are added or if the
        // order is changed. This can be important for serialization, databases, etc.
    }
}
