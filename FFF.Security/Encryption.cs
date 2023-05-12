using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Text;

namespace FFF.Security
{
    public static class Encryption
    {
        private const string Passphrase = "hy98219126ygu3297t39287yr93r8h8038ur0239ur38273273yr839283y92323hfbj3bsbd3273";

        private const int SaltLength = 3;

        private const long DateEncryptionFactor = 111999;

        public static long EncryptDate(DateTime dt)
        {
            var dateValue = long.Parse(dt.ToString("yyyyMMdd"));
            dateValue *= DateEncryptionFactor;
            return dateValue;
        }

        public static DateTime DecryptDate(long dateValue)
        {
            var afetrFacrot = dateValue / DateEncryptionFactor;
            var stringValue = afetrFacrot.ToString();
            var stringDate = string.Format("{0}/{1}/{2}", stringValue.Substring(0, 4), stringValue.Substring(4, 2),
                                           stringValue.Substring(6, 2));
            DateTime date;

            DateTime.TryParse(stringDate, out date);

            return date;
        }

        public static string EncryptString(string text)
        {
            return DoEncryptString(text);
        }

        public static string DecryptString(string text)
        {
            var decryptedText = DoDecryptString(text);

            if (!string.IsNullOrEmpty(decryptedText) && (text == decryptedText))
            {
                // Backward compatible in case the text is still use the old algorithm
                decryptedText = DoDecryptStringOld(text);
            }

            return decryptedText;

        }

        public static int DecodeRecordId(string safeRecordId)
        {
            int result;

            int.TryParse(DecryptString(safeRecordId.Replace(' ', '+')), out result);

            return result;
        }

        public static string EncodeRecordId(int recordId)
        {
            var result = EncryptString(recordId.ToString());

            return result;
        }

        public static string EncodeClaimImageUrl(string imageId)
        {
            return EncryptString(imageId);
        }

        public static string DecodeClaimImageUrl(string imageId)
        {
            return DecryptString(imageId);
        }

        public static bool CustomLifetimeValidator(DateTime? notBefore, DateTime? expires,
            SecurityToken tokenToValidate, TokenValidationParameters @param)
        {
            if (expires != null)
            {
                return expires > DateTime.UtcNow;
            }
            return false;
        }

        #region Helper

        internal static string DoEncryptString(string text)
        {
            byte[] results;
            var utf8 = new UTF8Encoding();

            // Step 1. We hash the passphrase using MD5
            // We use the MD5 hash generator as the result is a 128 bit byte array
            // which is a valid length for the TripleDES encoder we use below
            var hashProvider = new MD5CryptoServiceProvider();
            var tdesKey = hashProvider.ComputeHash(utf8.GetBytes(Passphrase));

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            // Step 3. Setup the encoder
            var tdesAlgorithm = new TripleDESCryptoServiceProvider
            {
                Key = tdesKey,
                Mode = CipherMode.CBC,
                IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 }
            };

            // Step 4. Convert the input string to a byte[]
            var dataToEncrypt = utf8.GetBytes(AddSalt(text));

            // Step 5. Attempt to encrypt the string
            try
            {
                var encryptor = tdesAlgorithm.CreateEncryptor();
                results = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
            }
            finally
            {
                // Clear the TripleDes and Hashprovider services of any sensitive information
                tdesAlgorithm.Clear();
                hashProvider.Clear();
            }

            // Step 6. Return the encrypted string as a base64 encoded string
            return Convert.ToBase64String(results, 0, results.Length);
        }

        internal static string DoDecryptString(string text)
        {
            // Pre-condition
            if (string.IsNullOrEmpty(text)) return text;

            // Encrypted text is Base-64 string. The length of a base64 encoded string is always a multiple of 4.
            // If the length is not multiple of 4, it can't be decrypted.
            if (text.Length % 4 > 0) return text;

            byte[] results;
            var utf8 = new UTF8Encoding();

            // Step 1. We hash the passphrase using MD5
            // We use the MD5 hash generator as the result is a 128 bit byte array
            // which is a valid length for the TripleDES encoder we use below
            var hashProvider = new MD5CryptoServiceProvider();
            var tdesKey = hashProvider.ComputeHash(utf8.GetBytes(Passphrase));

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            // Step 3. Setup the decoder
            var tdesAlgorithm = new TripleDESCryptoServiceProvider
            {
                Key = tdesKey,
                Mode = CipherMode.CBC,
                IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 }
            };

            try
            {
                // Step 4. Convert the input string to a byte[]
                var dataToDecrypt = Convert.FromBase64String(text);

                // Step 5. Attempt to decrypt the string
                var decryptor = tdesAlgorithm.CreateDecryptor();
                results = decryptor.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
            }
            catch
            {
                return text;
            }
            finally
            {
                // Clear the TripleDes and Hash provider services of any sensitive information
                tdesAlgorithm.Clear();
                hashProvider.Clear();
            }

            // Step 6. Return the decrypted string in UTF8 format
            return RemoveSalt(utf8.GetString(results));
        }

        internal static string DoEncryptStringOld(string text)
        {
            byte[] results;
            var utf8 = new UTF8Encoding();

            // Step 1. We hash the passphrase using MD5
            // We use the MD5 hash generator as the result is a 128 bit byte array
            // which is a valid length for the TripleDES encoder we use below
            var hashProvider = new MD5CryptoServiceProvider();
            var tdesKey = hashProvider.ComputeHash(utf8.GetBytes(Passphrase));

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            var tdesAlgorithm = new TripleDESCryptoServiceProvider();

            // Step 3. Setup the encoder
            tdesAlgorithm.Key = tdesKey;
            tdesAlgorithm.Mode = CipherMode.ECB;
            tdesAlgorithm.Padding = PaddingMode.PKCS7;

            // Step 4. Convert the input string to a byte[]
            var dataToEncrypt = utf8.GetBytes(text);

            // Step 5. Attempt to encrypt the string
            try
            {
                var encryptor = tdesAlgorithm.CreateEncryptor();
                results = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
            }
            finally
            {
                // Clear the TripleDes and Hashprovider services of any sensitive information
                tdesAlgorithm.Clear();
                hashProvider.Clear();
            }

            // Step 6. Return the encrypted string as a base64 encoded string
            return Convert.ToBase64String(results, 0, results.Length);
        }

        internal static string DoDecryptStringOld(string text)
        {
            // Pre-condition
            if (string.IsNullOrEmpty(text)) return text;

            // Encrypted text is Base-64 string. The length of a base64 encoded string is always a multiple of 4.
            // If the length is not multiple of 4, it can't be decrypted.
            if (text.Length % 4 > 0) return text;

            byte[] results;
            var utf8 = new UTF8Encoding();

            // Step 1. We hash the passphrase using MD5
            // We use the MD5 hash generator as the result is a 128 bit byte array
            // which is a valid length for the TripleDES encoder we use below
            var hashProvider = new MD5CryptoServiceProvider();
            var tdesKey = hashProvider.ComputeHash(utf8.GetBytes(Passphrase));

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            // Step 3. Setup the decoder
            var tdesAlgorithm = new TripleDESCryptoServiceProvider
            {
                Key = tdesKey,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7,
            };

            try
            {
                // Step 4. Convert the input string to a byte[]
                var dataToDecrypt = Convert.FromBase64String(text);

                // Step 5. Attempt to decrypt the string
                var decryptor = tdesAlgorithm.CreateDecryptor();
                results = decryptor.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
            }
            catch
            {
                return text;
            }
            finally
            {
                // Clear the TripleDes and Hash provider services of any sensitive information
                tdesAlgorithm.Clear();
                hashProvider.Clear();
            }

            // Step 6. Return the decrypted string in UTF8 format
            return utf8.GetString(results);
        }

        internal static string AddSalt(string text)
        {
            var rndPrefix = new byte[SaltLength];
            var rndSuffix = new byte[SaltLength];

            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(rndPrefix);
            rng.GetBytes(rndSuffix);

            // This must use ASCII instead of UTF8 otherwise it would not generate the string which its length equal to SaltLength.
            var prefix = Encoding.ASCII.GetString(rndPrefix);
            var suffix = Encoding.ASCII.GetString(rndSuffix);

            return string.Format("{0}{1}{2}", prefix, text, suffix);
        }

        internal static string RemoveSalt(string text)
        {
            return text.Substring(SaltLength, text.Length - SaltLength * 2);
        }

        #endregion
    }
}
