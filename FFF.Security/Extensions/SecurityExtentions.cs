using System.Text;
using System.IO;
using System;
using System.Diagnostics;
using SshNet.Security.Cryptography;
using SSC = System.Security.Cryptography;

namespace FFF.Security
{
    public static class SecurityExtensions
    {
        /// <summary>
        /// Read and get the MD5 hash value of a given filename.
        /// </summary>
        /// <param name="filename">Full path and filename</param>
        /// <returns>Lowercase MD5 hash value, or empty string on error</returns>
        public static string GetMD5(this string filename)
        {
            try
            {
                using (FileStream fileStream = GetFileStream(filename))
                {
                    // Create a new instance of MD5CryptoServiceProvider to compute the hash
                    using (SSC.MD5CryptoServiceProvider md5Provider = new SSC.MD5CryptoServiceProvider())
                        // Compute the hash, convert it to a hexadecimal string, and return it in lowercase
                        return BitConverter.ToString(md5Provider.ComputeHash(fileStream)).Replace("-", string.Empty).ToLower();
                }
            }
            catch (Exception ex)
            {
                // Log the exception and return an empty string
                Trace.TraceError(ex.Message);
                return string.Empty;
            }
        }

        /// <summary>
        /// Computes the hash of a string using a specified hash algorithm.
        /// </summary>
        /// <param name="input">The string to hash</param>
        /// <param name="hashType">The hash algorithm to use</param>
        /// <returns>The resulting hash string, or an empty string on error</returns>
        public static string ComputeHash(this string input, HashType hashType)
        {
            try
            {
                // Get the hash as a byte array
                byte[] hash = GetHash(input, hashType);

                // Use StringBuilder for efficient string concatenation
                StringBuilder ret = new StringBuilder(hash.Length * 2);

                // Convert each byte in the hash to a two-digit hexadecimal string
                foreach (byte b in hash)
                    ret.Append(b.ToString("x2"));

                return ret.ToString();
            }
            catch (Exception ex)
            {
                // Log the exception and return an empty string
                Trace.TraceError(ex.Message);
                return string.Empty;
            }
        }

        /// <summary>
        /// Helper method to get a file stream with read and shared read access.
        /// </summary>
        /// <param name="pathName">The path of the file to open</param>
        /// <returns>A FileStream for the specified file</returns>
        private static FileStream GetFileStream(string pathName) =>
            new FileStream(pathName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        /// <summary>
        /// Helper method to compute the hash of a string given a HashType.
        /// </summary>
        /// <param name="input">The input string to hash</param>
        /// <param name="hash">The type of hash to use</param>
        /// <returns>The computed hash as a byte array</returns>
        private static byte[] GetHash(string input, HashType hash)
        {
            // Convert the input string into a byte array using ASCII encoding.
            // This is necessary as the hashing functions work with byte arrays.
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            // Switch on the hash type to determine which hashing algorithm to use.
            switch (hash)
            {
                // Each case creates an instance of the specified hash algorithm,
                // computes the hash of the input bytes, and returns the hash as a byte array.

                case HashType.HMAC:
                    return HMAC.Create().ComputeHash(inputBytes);

                case HashType.HMACMD5:
                    return HMACMD5.Create().ComputeHash(inputBytes);

                case HashType.HMACSHA1:
                    return HMACSHA1.Create().ComputeHash(inputBytes);

                case HashType.HMACSHA256:
                    return HMACSHA256.Create().ComputeHash(inputBytes);

                case HashType.HMACSHA384:
                    return HMACSHA384.Create().ComputeHash(inputBytes);

                case HashType.HMACSHA512:
                    return HMACSHA512.Create().ComputeHash(inputBytes);

                case HashType.MACTripleDES:
                    // MACTripleDES hash algorithm is not implemented in this method.
                    // If this case is reached, an exception is thrown.
                    throw new NotImplementedException();

                case HashType.MD5:
                    return MD5.Create().ComputeHash(inputBytes);

                case HashType.RIPEMD160:
                    return RIPEMD160.Create().ComputeHash(inputBytes);

                case HashType.SHA1:
                    return SHA1.Create().ComputeHash(inputBytes);

                case HashType.SHA256:
                    return SHA256.Create().ComputeHash(inputBytes);

                case HashType.SHA384:
                    return SHA384.Create().ComputeHash(inputBytes);

                case HashType.SHA512:
                    return SHA512.Create().ComputeHash(inputBytes);

                default:
                    // If the hash type provided does not match any of the cases,
                    // the method returns the original byte array without hashing.
                    return inputBytes;
            }
        }

        /// <summary>
        /// Encrypts a string using RSA encryption with the provided key.
        /// </summary>
        /// <param name="stringToEncrypt">String to be encrypted.</param>
        /// <param name="key">Encryption key.</param>
        /// <returns>Encrypted string in hexadecimal format.</returns>
        /// <exception cref="ArgumentException">Thrown when input string or key is null or empty.</exception>
        public static string Encrypt(this string stringToEncrypt, string key)
        {
            if (string.IsNullOrEmpty(stringToEncrypt))
                throw new ArgumentException("An empty string value cannot be encrypted.");

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Cannot encrypt using an empty key. Please supply an encryption key.");

            // Utilize using statement for automatic disposal of resources
            using (SSC.RSACryptoServiceProvider rsa = new SSC.RSACryptoServiceProvider(new SSC.CspParameters { KeyContainerName = key }))
            {
                rsa.PersistKeyInCsp = true;

                // Convert the string to a byte array using UTF8 encoding
                byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(stringToEncrypt);

                // Encrypt the byte array and return as a hexadecimal string
                byte[] encryptedBytes = rsa.Encrypt(bytesToEncrypt, true);
                return BitConverter.ToString(encryptedBytes).Replace("-", "");
            }
        }

        /// <summary>
        /// Decrypts a string using RSA decryption with the provided key.
        /// </summary>
        /// <param name="stringToDecrypt">String to be decrypted.</param>
        /// <param name="key">Decryption key.</param>
        /// <returns>Decrypted string, or null if decryption fails.</returns>
        /// <exception cref="ArgumentException">Thrown when input string or key is null or empty.</exception>
        public static string Decrypt(this string stringToDecrypt, string key)
        {
            if (string.IsNullOrEmpty(stringToDecrypt))
                throw new ArgumentException("An empty string value cannot be decrypted.");

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Cannot decrypt using an empty key. Please supply a decryption key.");

            try
            {
                // Utilize using statement for automatic disposal of RSACryptoServiceProvider
                using (SSC.RSACryptoServiceProvider rsa = new SSC.RSACryptoServiceProvider(new SSC.CspParameters { KeyContainerName = key }))
                {
                    rsa.PersistKeyInCsp = true;

                    // Convert the hexadecimal string back to a byte array
                    byte[] bytesToDecrypt = ConvertHexStringToByteArray(stringToDecrypt);

                    // Decrypt the byte array and return the original string
                    byte[] decryptedBytes = rsa.Decrypt(bytesToDecrypt, true);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            catch
            {
                // If decryption fails, return null
                return null;
            }
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hexString">The hexadecimal string to convert.</param>
        /// <returns>A byte array representing the hexadecimal string.</returns>
        private static byte[] ConvertHexStringToByteArray(string hexString)
        {
            int numberChars = hexString.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
