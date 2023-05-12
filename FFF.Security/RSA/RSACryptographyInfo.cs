using System;

namespace FFF.Security.RSA
{
    [Serializable]
    public class RSACryptographyInfo
    {
        public RSACryptographyInfo()
        {
            Key = new RSAKeyInfo();
        }

        private byte[] _hashSecretBytes
        {
            get
            {
                if (string.IsNullOrEmpty(Secret)) return null;
                return RSACryptography.CreateHashedSecret(Secret);
            }
        }

        public string Secret { get; set; }
        public RSAKeyInfo Key { get; set; }

        public string EncryptedSecret
        {
            get
            {
                if (string.IsNullOrEmpty(Secret) ||
                    string.IsNullOrEmpty(Key.PublicKey) ||
                    !VerifySignatureHash) return string.Empty;
                return RSACryptography.RsaEncryptionPKCS1(Secret, Key.PublicKey);
            }
            set => EncryptedSecret = value;
        }
        public string DecryptSecret
        {
            get
            {
                if (string.IsNullOrEmpty(Secret) ||
                    string.IsNullOrEmpty(Key.PrivateKey) ||
                    !VerifySignatureHash) return string.Empty;
                return RSACryptography.RsaDecryptionPKCS1(Secret, Key.PrivateKey);
            }
            set => DecryptSecret = value;
        }
        public string SignatureHash
        {
            get
            {
                if (string.IsNullOrEmpty(Secret) || string.IsNullOrEmpty(Key.PrivateKey)) return string.Empty;
                return RSACryptography.CreateSignatureHashSHA256(Secret, Key.PrivateKey);
            }
        }
        public bool VerifySignatureHash
        {
            get
            {
                if (string.IsNullOrEmpty(Secret) ||
                    string.IsNullOrEmpty(Key.PublicKey)) return false;
                return RSACryptography.VerifySignatureHashSHA256(Secret, SignatureHash, Key.PublicKey);
            }
        }
    }
}
