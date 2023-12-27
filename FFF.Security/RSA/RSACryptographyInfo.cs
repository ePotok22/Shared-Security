using System;

namespace FFF.Security.RSA
{
    /// <summary>
    /// Represents cryptographic information for RSA encryption and decryption,
    /// including the key information and secret to be encrypted/decrypted.
    /// </summary>
    [Serializable]
    public class RSACryptographyInfo
    {
        /// <summary>
        /// Initializes a new instance of the RSACryptographyInfo class.
        /// </summary>
        public RSACryptographyInfo()
        {
            Key = new RSAKeyInfo();
        }

        /// <summary>
        /// Gets the hashed secret bytes.
        /// </summary>
        /// <returns>Hashed secret as byte array or null if the Secret is null or empty.</returns>
        private byte[] GetHashSecretBytes()
        {
            if (string.IsNullOrEmpty(Secret)) return null;
            return RSACryptography.CreateHashedSecret(Secret);
        }

        /// <summary>
        /// Gets or sets the secret string to be used in cryptographic operations.
        /// </summary>
        public string Secret { get; set; }

        /// <summary>
        /// Gets or sets the RSA key information including public and private keys.
        /// </summary>
        public RSAKeyInfo Key { get; set; }

        /// <summary>
        /// Gets the encrypted version of the secret using RSA public key.
        /// </summary>
        /// <returns>Encrypted secret string or empty string if conditions are not met.</returns>
        public string EncryptedSecret => GetEncryptedSecret();

        /// <summary>
        /// Helper method to encrypt the secret using RSA public key.
        /// </summary>
        /// <returns>Encrypted secret string or empty string if conditions are not met.</returns>
        private string GetEncryptedSecret()
        {
            if (string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Key.PublicKey)) return string.Empty;
            return RSACryptography.RsaEncryptionPKCS1(Secret, Key.PublicKey);
        }

        /// <summary>
        /// Gets the decrypted version of the secret using RSA private key.
        /// </summary>
        /// <returns>Decrypted secret string or empty string if conditions are not met.</returns>
        public string DecryptSecret => GetDecryptedSecret();

        /// <summary>
        /// Helper method to decrypt the secret using RSA private key.
        /// </summary>
        /// <returns>Decrypted secret string or empty string if conditions are not met.</returns>
        private string GetDecryptedSecret()
        {
            if (string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Key.PrivateKey)) return string.Empty;
            return RSACryptography.RsaDecryptionPKCS1(Secret, Key.PrivateKey);
        }

        /// <summary>
        /// Gets the signature hash of the secret using RSA private key.
        /// </summary>
        /// <returns>Signature hash string or empty string if conditions are not met.</returns>
        public string SignatureHash => GetSignatureHash();

        /// <summary>
        /// Helper method to generate a signature hash for the secret using RSA private key.
        /// </summary>
        /// <returns>Signature hash string or empty string if conditions are not met.</returns>
        private string GetSignatureHash()
        {
            if (string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Key.PrivateKey)) return string.Empty;
            return RSACryptography.CreateSignatureHashSHA256(Secret, Key.PrivateKey);
        }

        /// <summary>
        /// Verifies the signature hash of the secret using RSA public key.
        /// </summary>
        /// <returns>True if the signature hash is verified, otherwise false.</returns>
        public bool VerifySignatureHash => GetVerifySignatureHash();

        /// <summary>
        /// Helper method to verify the signature hash of the secret using RSA public key.
        /// </summary>
        /// <returns>True if the signature hash is verified, otherwise false.</returns>
        private bool GetVerifySignatureHash()
        {
            if (string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Key.PublicKey)) return false;
            return RSACryptography.VerifySignatureHashSHA256(Secret, SignatureHash, Key.PublicKey);
        }
    }
}
