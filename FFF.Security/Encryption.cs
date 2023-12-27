using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace FFF.Security
{
    public static class Encryption
    {
        // Constants used across the class.
        private const string Passphrase = "hy98219126ygu3297t39287yr93r8h8038ur0239ur38273273yr839283y92323hfbj3bsbd3273";
        private const int SaltLength = 3;
        private const long DateEncryptionFactor = 111999;
        private const string DateFormat = "yyyyMMdd";

        /// <summary>
        /// Encrypts a DateTime object into a long representation.
        /// </summary>
        /// <param name="dt">The DateTime object to be encrypted.</param>
        /// <returns>A long representing the encrypted date.</returns>
        public static long EncryptDate(DateTime dt) =>
            long.Parse(dt.ToString(DateFormat)) * DateEncryptionFactor;

        /// <summary>
        /// Decrypts a long representation of a date back to a DateTime object.
        /// </summary>
        /// <param name="dateValue">The encrypted date as a long.</param>
        /// <returns>The decrypted DateTime object.</returns>
        public static DateTime DecryptDate(long dateValue)
        {
            string stringValue = (dateValue / DateEncryptionFactor).ToString("00000000");
            if (DateTime.TryParseExact(stringValue, DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime date))
                return date;

            throw new FormatException("Invalid encrypted date value.");
        }

        /// <summary>
        /// Encrypts a string using a predefined encryption algorithm.
        /// </summary>
        /// <param name="text">The text to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        public static string EncryptString(string text) =>
            DoEncryptString(text);

        // <summary>
        /// Decrypts a string using a predefined decryption algorithm.
        /// Supports backward compatibility with an old decryption method.
        /// </summary>
        /// <param name="text">The text to decrypt.</param>
        /// <returns>The decrypted string.</returns>
        public static string DecryptString(string text)
        {
            string decryptedText = DoDecryptString(text);

            if (!string.IsNullOrEmpty(decryptedText) && text.Equals(decryptedText))
                decryptedText = DoDecryptStringOld(text);

            return decryptedText;
        }

        /// <summary>
        /// Decodes an encrypted record ID into an integer.
        /// </summary>
        /// <param name="safeRecordId">The encrypted record ID as a string.</param>
        /// <returns>The decoded integer ID.</returns>
        public static int DecodeRecordId(string safeRecordId)
        {
            if (safeRecordId.Contains(' '))
                safeRecordId = safeRecordId.Replace(' ', '+');

            if (int.TryParse(DecryptString(safeRecordId), out int result))
                return result;

            throw new FormatException("Invalid encrypted record ID.");
        }

        /// <summary>
        /// Encodes a record ID into an encrypted string.
        /// </summary>
        /// <param name="recordId">The record ID to encode.</param>
        /// <returns>The encoded record ID as a string.</returns>
        public static string EncodeRecordId(int recordId) =>
            DoEncryptString(recordId.ToString());

        /// <summary>
        /// Encrypts an image ID to be used in a URL.
        /// </summary>
        /// <param name="imageId">The image ID to encrypt.</param>
        /// <returns>The encrypted image ID.</returns>
        public static string EncodeClaimImageUrl(string imageId) =>
            DoEncryptString(imageId);

        // <summary>
        /// Decrypts an encrypted image ID used in a URL.
        /// </summary>
        /// <param name="imageId">The encrypted image ID to decrypt.</param>
        /// <returns>The decrypted image ID.</returns>
        public static string DecodeClaimImageUrl(string imageId) =>
            DecryptString(imageId);

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
