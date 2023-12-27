using System;

namespace FFF.Security.RSA
{
    /// <summary>
    /// Represents the key information for RSA cryptography, including both public and private keys.
    /// The class is serializable, which allows it to be easily converted to and from a byte stream.
    /// This can be useful for storing or transmitting the key information securely.
    /// </summary>
    [Serializable]
    public class RSAKeyInfo
    {
        /// <summary>
        /// Gets or sets the public key of the RSA key pair.
        /// The public key is used in public key cryptography, primarily for encrypting data.
        /// This key is typically shared or transmitted and should be stored in a format that facilitates this.
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the private key of the RSA key pair.
        /// The private key is used for decrypting data that was encrypted using the corresponding public key.
        /// It is crucial to keep this key confidential and secure, as it should never be exposed or transmitted unnecessarily.
        /// </summary>
        public string PrivateKey { get; set; }
    }
}
