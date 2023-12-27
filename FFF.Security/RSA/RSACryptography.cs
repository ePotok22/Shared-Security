using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace FFF.Security.RSA
{
    /// <summary>
    /// This class provides RSA cryptographic functions, including RSA key generation, encryption,
    /// decryption, and handling of cryptographic data structures. It serves as a utility class for
    /// RSA encryption and decryption operations using PKCS1 standards.
    /// </summary>
    public sealed class RSACryptography
    {
        // Constants for RSA provider type and key exchange.
        private const int DefaultKeyLength = 1024;
        private const int ProvRsaFull = 1;
        private const int AtKeyExchange = 1;
        private const string StringEmpty = "";
        private const string N = "N";
        private const string SHA256 = "SHA256";

        /// <summary>
        /// Creates a new instance of the RSACryptoServiceProvider with a specified key length.
        /// This instance is configured for key exchange purposes.
        /// </summary>
        /// <param name="keyLength">The length of the RSA key, defaults to 1024 bits.</param>
        /// <returns>An instance of RSACryptoServiceProvider configured with the specified key length.</returns>
        public static RSACryptoServiceProvider CreateRsaProviderPKCS1(int keyLength = DefaultKeyLength)
        {
            CspParameters csp = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(N),
                ProviderType = ProvRsaFull,
                KeyNumber = AtKeyExchange
            };

            return new RSACryptoServiceProvider(keyLength, csp)
            {
                PersistKeyInCsp = false
            };
        }

        // <summary>
        /// Generates RSA cryptography information including keys and the secret for encryption or decryption.
        /// This method can optionally use an existing RSA provider or create a new one.
        /// </summary>
        /// <param name="secret">The secret text to be encrypted or decrypted.</param>
        /// <param name="publicKey">Optional parameter for the public key.</param>
        /// <param name="privateKey">Optional parameter for the private key.</param>
        /// <param name="rsaProvider">Optional RSA provider to generate keys.</param>
        /// <returns>A RSACryptographyInfo object containing RSA cryptographic data.</returns>
        public static RSACryptographyInfo GetRsaCryptoInfo(string secret, string publicKey = StringEmpty, string privateKey = StringEmpty, RSACryptoServiceProvider rsaProvider = null)
        {
            try
            {
                RSACryptoServiceProvider rsa = rsaProvider ?? CreateRsaProviderPKCS1();
                if (rsa != null)
                {
                    return new RSACryptographyInfo
                    {
                        Secret = secret,
                        Key = new RSAKeyInfo()
                        {
                            PrivateKey = string.IsNullOrEmpty(publicKey)
                                ? ExportPrivateKeyToRSAPEM(rsa)?.Replace(Environment.NewLine, StringEmpty)
                                : privateKey,
                            PublicKey = string.IsNullOrEmpty(privateKey)
                                ? ExportPublicKeyToRSAPEM(rsa)?.Replace(Environment.NewLine, StringEmpty)
                                : publicKey,
                        }
                    };
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.Message);
            }
            return new RSACryptographyInfo()
            {
                Secret = secret,
                Key = GenerateRsaKey()
            };
        }

        /// <summary>
        /// Encrypts a given secret using RSA encryption with a specified public key.
        /// </summary>
        /// <param name="secret">The secret text to be encrypted.</param>
        /// <param name="publicKeyStr">The public key string for encryption.</param>
        /// <returns>The encrypted string or an empty string if encryption fails.</returns>
        public static string RsaEncryptionPKCS1(string secret, string publicKeyStr)
        {
            try
            {
                RSACryptoServiceProvider publicRSAkey = DecodeRsaPublicKey(publicKeyStr);
                return EncryptString(secret, publicRSAkey);
            }
            catch (Exception)
            {
                return StringEmpty;
            }
        }

        /// <summary>
        /// Decrypts an encrypted secret using RSA decryption with a specified private key.
        /// </summary>
        /// <param name="encryptedSecret">The encrypted secret text to be decrypted.</param>
        /// <param name="privateKeyStr">The private key string for decryption.</param>
        /// <returns>The decrypted string or an empty string if decryption fails.</returns>
        public static string RsaDecryptionPKCS1(string encryptedsecret, string privateKeyStr)
        {
            try
            {
                RSACryptoServiceProvider privateRSAkey = DecodeRsaPrivateKey(privateKeyStr);
                return DecryptString(encryptedsecret, privateRSAkey);
            }
            catch (Exception)
            {
                return StringEmpty;
            }
        }

        /// <summary>
        /// Creates a hashed representation of a secret using SHA256.
        /// </summary>
        /// <param name="secret">The secret text to hash.</param>
        /// <returns>A byte array containing the hashed secret or null in case of failure.</returns>
        public static byte[] CreateHashedSecret(string secret)
        {
            try
            {
                SHA256Managed sha256 = new SHA256Managed();
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Creates a signature hash for a secret using SHA256 and a private key.
        /// </summary>
        /// <param name="secret">The secret to be hashed.</param>
        /// <param name="privateKeyStr">The private key string used for hashing.</param>
        /// <returns>The signature hash as a string or an empty string if it fails.</returns>
        public static string CreateSignatureHashSHA256(string secret, string privateKeyStr)
        {
            try
            {
                RSACryptoServiceProvider rsa = DecodeRsaPrivateKey(privateKeyStr);
                byte[] signatureHashbytes = rsa.SignHash(CreateHashedSecret(secret), CryptoConfig.MapNameToOID(SHA256));
                return Convert.ToBase64String(signatureHashbytes);
            }
            catch
            {
                return StringEmpty;
            }
        }

        /// <summary>
        /// Verifies a signature hash against a secret using SHA256 and a public key.
        /// </summary>
        /// <param name="secret">The original secret string.</param>
        /// <param name="signature">The signature hash to be verified.</param>
        /// <param name="publicKeyStr">The public key string used for verification.</param>
        /// <returns>True if the signature is verified, false otherwise.</returns>
        public static bool VerifySignatureHashSHA256(string secret, string signature, string publicKeyStr)
        {
            try
            {
                RSACryptoServiceProvider rsa = DecodeRsaPublicKey(publicKeyStr);
                return rsa.VerifyHash(CreateHashedSecret(secret), CryptoConfig.MapNameToOID(SHA256), Convert.FromBase64String(signature));
            }
            catch (Exception)
            {
                return false;
            }

        }

        /// <summary>
        /// Generates RSA key information using an existing or new RSACryptoServiceProvider.
        /// </summary>
        /// <param name="rsaProvider">Optional RSA provider for generating the key information.</param>
        /// <returns>An RSAKeyInfo object containing public and private key information.</returns>
        public static RSAKeyInfo GenerateRsaKey(RSACryptoServiceProvider rsaProvider = null)
        {
            RSACryptoServiceProvider rsa = rsaProvider ?? CreateRsaProviderPKCS1();
            if (rsa == null) return new RSAKeyInfo();
            return new RSAKeyInfo()
            {
                PublicKey = ExportPublicKeyToRSAPEM(rsa)?.Replace(Environment.NewLine, StringEmpty) ?? StringEmpty,
                PrivateKey = ExportPrivateKeyToRSAPEM(rsa)?.Replace(Environment.NewLine, StringEmpty) ?? StringEmpty
            };
        }

        #region Helper

        internal static string PEMheader(PEMTypes p)
        {
            if (p == PEMTypes.PEM_SSH2_PUBLIC)
            {
                return "---- BEGIN " + PEMs[p] + " ----";
            }
            else
            {
                return "-----BEGIN " + PEMs[p] + "-----";
            }
        }

        internal static string PEMfooter(PEMTypes p)
        {
            if (p == PEMTypes.PEM_SSH2_PUBLIC)
            {
                return "---- END " + PEMs[p] + " ----";
            }
            else
            {
                return "-----END " + PEMs[p] + "-----";
            }
        }

        internal static PEMTypes GetPEMType(string pemString)
        {
            foreach (PEMTypes d in Enum.GetValues(typeof(PEMTypes)))
            {
                if (pemString.Contains(PEMheader(d)) && pemString.Contains(PEMfooter(d))) return d;
            }
            return PEMTypes.UNKNOWN;
        }

        internal static byte[] GetBytesFromPEM(string pemString, PEMTypes type, out Dictionary<string, string> extras)
        {
            extras = new Dictionary<string, string>();
            string header; string footer;
            string data = "";
            header = PEMheader(type);
            footer = PEMfooter(type);

            foreach (string s in pemString.Replace("\r", "").Split('\n'))
            {
                if (s.Contains(":"))
                {
                    extras.Add(s.Substring(0, s.IndexOf(":") - 1), s.Substring(s.IndexOf(":") + 1));
                }
                else
                {
                    if (s != "") data += s + "\n";
                }
            }

            int start = data.IndexOf(header) + header.Length;
            int end = data.IndexOf(footer, start) - start;

            return Convert.FromBase64String(data.Substring(start, end));
        }

        internal static byte[] GetBytesFromPEM(string pemString, out Dictionary<string, string> extras)
        {
            PEMTypes type = GetPEMType(pemString);
            return GetBytesFromPEM(pemString, type, out extras);
        }

        internal static byte[] GetBytesFromPEM(string pemString)
        {
            PEMTypes keyType = GetPEMType(pemString);
            Dictionary<string, string> extras;
            if (keyType == PEMTypes.UNKNOWN) return null;
            return GetBytesFromPEM(pemString, keyType, out extras);
        }

        internal static string PackagePEM(byte[] bytes, PEMTypes type)
        {
            TextWriter outputStream = new StringWriter();
            outputStream.NewLine = "\n";

            var base64 = Convert.ToBase64String(bytes, 0, (int)bytes.Length).ToCharArray();
            outputStream.WriteLine(PEMheader(type));

            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine(PEMfooter(type));
            return outputStream.ToString();

        }

        internal static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        internal static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        internal static int DecodeIntegerSize(System.IO.BinaryReader rd)
        {
            byte byteValue;
            int count;

            byteValue = rd.ReadByte();
            if (byteValue != 0x02)        // indicates an ASN.1 integer value follows
                return 0;

            byteValue = rd.ReadByte();
            if (byteValue == 0x81)
            {
                count = rd.ReadByte();    // data size is the following byte
            }
            else if (byteValue == 0x82)
            {
                byte hi = rd.ReadByte();  // data size in next 2 bytes
                byte lo = rd.ReadByte();
                count = BitConverter.ToUInt16(new[] { lo, hi }, 0);
            }
            else
            {
                count = byteValue;        // we already have the data size
            }

            //remove high order zeros in data
            while (rd.ReadByte() == 0x00)
            {
                count -= 1;
            }
            rd.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);

            return count;
        }

        internal static byte[] AlignBytes(byte[] inputBytes, int alignSize)
        {
            int inputBytesSize = inputBytes.Length;

            if ((alignSize != -1) && (inputBytesSize < alignSize))
            {
                byte[] buf = new byte[alignSize];
                for (int i = 0; i < inputBytesSize; ++i)
                {
                    buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
                }
                return buf;
            }
            else
            {
                return inputBytes;      // Already aligned, or doesn't need alignment
            }
        }

        public static string EncryptString(string inputString, RSACryptoServiceProvider key)
        {
            return EncryptBytes(Encoding.UTF32.GetBytes(inputString), key);
        }

        public static string EncryptBytes(byte[] bytes, RSACryptoServiceProvider key)
        {
            // TODO: Add Proper Exception Handlers
            //RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
            //rsaCryptoServiceProvider.FromXmlString(xmlString);
            //int keySize = dwKeySize / 8;
            int keySize = key.KeySize / 8;

            // The hash function in use by the .NET RSACryptoServiceProvider here is SHA1
            // int maxLength = ( keySize ) - 2 - ( 2 * SHA1.Create().ComputeHash( rawBytes ).Length );
            int maxLength = keySize - 42;
            int dataLength = bytes.Length;
            int iterations = dataLength / maxLength;
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i <= iterations; i++)
            {
                byte[] tempBytes = new byte[(dataLength - maxLength * i > maxLength) ? maxLength : dataLength - maxLength * i];
                Buffer.BlockCopy(bytes, maxLength * i, tempBytes, 0, tempBytes.Length);
                byte[] encryptedBytes = key.Encrypt(tempBytes, true);
                // Be aware the RSACryptoServiceProvider reverses the order of encrypted bytes after encryption and before decryption.
                // If you do not require compatibility with Microsoft Cryptographic API (CAPI) and/or other vendors.
                // Comment out the next line and the corresponding one in the DecryptString function.
                Array.Reverse(encryptedBytes);
                // Why convert to base 64?
                // Because it is the largest power-of-two base printable using only ASCII characters
                stringBuilder.Append(Convert.ToBase64String(encryptedBytes));
            }
            return stringBuilder.ToString();
        }

        internal static string DecryptString(string inputString, RSACryptoServiceProvider key)
        {
            return Encoding.UTF32.GetString(DecryptBytes(inputString, key));
        }

        internal static byte[] DecryptBytes(string inputString, RSACryptoServiceProvider key)
        {
            // TODO: Add Proper Exception Handlers
            //RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
            //rsaCryptoServiceProvider.FromXmlString(xmlString);
            int base64BlockSize = ((key.KeySize / 8) % 3 != 0) ? (((key.KeySize / 8) / 3) * 4) + 4 : ((key.KeySize / 8) / 3) * 4;
            int iterations = inputString.Length / base64BlockSize;
            ArrayList arrayList = new ArrayList();
            for (int i = 0; i < iterations; i++)
            {
                byte[] encryptedBytes = Convert.FromBase64String(inputString.Substring(base64BlockSize * i, base64BlockSize));
                // Be aware the RSACryptoServiceProvider reverses the order of encrypted bytes after encryption and before decryption.
                // If you do not require compatibility with Microsoft Cryptographic API (CAPI) and/or other vendors.
                // Comment out the next line and the corresponding one in the EncryptString function.
                Array.Reverse(encryptedBytes);
                arrayList.AddRange(key.Decrypt(encryptedBytes, true));
            }
            return arrayList.ToArray(Type.GetType("System.Byte")) as byte[];
        }

        internal static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
        {
            MemoryStream memst = new MemoryStream();
            TripleDES alg = TripleDES.Create();
            alg.Key = desKey;
            alg.IV = IV;
            try
            {
                CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(cipherData, 0, cipherData.Length);
                cs.Close();
            }
            catch
            {
                return null;
            }
            byte[] decryptedData = memst.ToArray();
            return decryptedData;
        }

        internal static byte[] DecryptRSAPrivatePEM(byte[] privateKey, byte[] salt, SecureString despswd)
        {

            //------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

            //SecureString despswd = new SecureString(); // GetSecPswd("Enter password to derive 3DES key==>");
            //foreach (char c in "password")
            //    despswd.AppendChar(c);

            //Console.Write("\nEnter password to derive 3DES key: ");
            //String pswd = Console.ReadLine();
            byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
            if (deskey == null)
                return null;
            //showBytes("3DES key", deskey) ;

            //------ Decrypt the encrypted 3des-encrypted RSA private key ------
            byte[] rsakey = DecryptKey(privateKey, deskey, salt);	//OpenSSL uses salt value in PEM header also as 3DES IV
            if (rsakey != null)
                return rsakey;	//we have a decrypted RSA private key
            else
            {
                return null;
            }
        }

        private static byte[] GetOpenSSL3deskey(byte[] salt, SecureString secpswd, int count, int miter)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            int HASHLENGTH = 16;	//MD5 bytes
            byte[] keymaterial = new byte[HASHLENGTH * miter];     //to store contatenated Mi hashed results

            byte[] psbytes = new byte[secpswd.Length];
            unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
            Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

            //UTF8Encoding utf8 = new UTF8Encoding();
            //byte[] psbytes = utf8.GetBytes(pswd);

            // --- contatenate salt and pswd bytes into fixed data array ---
            byte[] data00 = new byte[psbytes.Length + salt.Length];
            Array.Copy(psbytes, data00, psbytes.Length);		//copy the pswd bytes
            Array.Copy(salt, 0, data00, psbytes.Length, salt.Length);	//concatenate the salt bytes

            // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = null;
            byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

            for (int j = 0; j < miter; j++)
            {
                // ----  Now hash consecutively for count times ------
                if (j == 0)
                    result = data00;   	//initialize
                else
                {
                    Array.Copy(result, hashtarget, result.Length);
                    Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                    result = hashtarget;
                    //Console.WriteLine("Updated new initial hash target:") ;
                    //showBytes(result) ;
                }

                for (int i = 0; i < count; i++)
                    result = md5.ComputeHash(result);
                Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //contatenate to keymaterial
            }
            //showBytes("Final key material", keymaterial);
            byte[] deskey = new byte[24];
            Array.Copy(keymaterial, deskey, deskey.Length);

            Array.Clear(psbytes, 0, psbytes.Length);
            Array.Clear(data00, 0, data00.Length);
            Array.Clear(result, 0, result.Length);
            Array.Clear(hashtarget, 0, hashtarget.Length);
            Array.Clear(keymaterial, 0, keymaterial.Length);

            return deskey;
        }

        internal static string ExportPrivateKeyToRSAPEM(RSACryptoServiceProvider csp) // PKCS1
        {
            TextWriter outputStream = new StringWriter();

            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return PackagePEM(stream.GetBuffer(), PEMTypes.PEM_RSA);
            }
        }

        internal static string ExportPublicKeyToRSAPEM(RSACryptoServiceProvider csp)   // PKCS1
        {
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);

                    //All Parameter Must Have Value so Set Other Parameter Value Whit Invalid Data  (for keeping Key Structure  use "parameters.Exponent" value for invalid data)
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.D
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.P
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.Q
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.DP
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.DQ
                    EncodeIntegerBigEndian(innerWriter, Guid.NewGuid().ToByteArray()); // instead of parameters.InverseQ

                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return PackagePEM(stream.GetBuffer(), PEMTypes.PEM_RSA_PUBLIC);
            }
        }

        internal static RSACryptoServiceProvider DecodeRsaPublicKey(string publicKey)
        {
            return DecodeRsaPublicKey(GetBytesFromPEM(publicKey));
        }

        internal static RSACryptoServiceProvider DecodeRsaPublicKey(byte[] publicKeyBytes)   // PKCS1
        {
            MemoryStream ms = new MemoryStream(publicKeyBytes);
            BinaryReader rd = new BinaryReader(ms);
            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:     // Improper ASN.1 format
                        return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue != 0x0102) // (version number)
                {    // Improper ASN.1 format, unexpected version number
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {     // Improper ASN.1 format
                    return null;
                }

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(DecodeIntegerSize(rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraitsInfo traits = new RSAParameterTraitsInfo(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = AlignBytes(rsAparams.Modulus, traits.SizeMod);
                rsAparams.Exponent = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeExp);
                //rsAparams.D = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_D);
                //rsAparams.P = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_P);
                //rsAparams.Q = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Q);
                //rsAparams.DP = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DP);
                //rsAparams.DQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DQ);
                //rsAparams.InverseQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_InvQ);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch
            {
                return null;
            }
            finally
            {
                rd.Close();
            }
        }

        internal static RSACryptoServiceProvider DecodeRsaPrivateKey(string privateKey, string password = "")
        {
            Dictionary<string, string> extras = new Dictionary<string, string>();
            byte[] bytes = GetBytesFromPEM(privateKey, out extras);

            if (extras.Any(x => x.Value.Contains("ENCRYPTED")) && extras.Any(x => x.Key.Contains("DEK-Inf")))
            {
                String saltstr = extras.First(x => x.Key.Contains("DEK-Inf")).Value.Split(',')[1].Trim();
                byte[] salt = new byte[saltstr.Length / 2];

                for (int i = 0; i < salt.Length; i++)
                    salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                SecureString despswd = new SecureString(); // GetSecPswd("Enter password to derive 3DES key==>");
                foreach (char c in password)
                    despswd.AppendChar(c);
                byte[] decoded = DecryptRSAPrivatePEM(bytes, salt, despswd);
                bytes = decoded;
            }

            return DecodeRsaPrivateKey(bytes);
        }

        internal static RSACryptoServiceProvider DecodeRsaPrivateKey(byte[] privateKeyBytes)// PKCS1
        {
            MemoryStream ms = new MemoryStream(privateKeyBytes);
            BinaryReader rd = new BinaryReader(ms);

            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:     // Improper ASN.1 format
                        return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue != 0x0102) // (version number)
                {     // Improper ASN.1 format, unexpected version number
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {     // Improper ASN.1 format
                    return null;
                }

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(DecodeIntegerSize(rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraitsInfo traits = new RSAParameterTraitsInfo(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = AlignBytes(rsAparams.Modulus, traits.SizeMod);
                rsAparams.Exponent = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeExp);
                rsAparams.D = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeD);
                rsAparams.P = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeP);
                rsAparams.Q = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeDQ);
                rsAparams.DP = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeDP);
                rsAparams.DQ = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeDQ);
                rsAparams.InverseQ = AlignBytes(rd.ReadBytes(DecodeIntegerSize(rd)), traits.SizeInvQ);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch
            {
                return null;
            }
            finally
            {
                rd.Close();
            }
        }

        internal static Dictionary<PEMTypes, string> PEMs = new Dictionary<PEMTypes, string>()
        {
            {PEMTypes.PEM_X509_OLD , "X509 CERTIFICATE"},
            {PEMTypes.PEM_X509 , "CERTIFICATE"},
            {PEMTypes.PEM_X509_PAIR , "CERTIFICATE PAIR"},
            {PEMTypes.PEM_X509_TRUSTED , "TRUSTED CERTIFICATE"},
            {PEMTypes.PEM_X509_REQ_OLD , "NEW CERTIFICATE REQUEST"},
            {PEMTypes.PEM_X509_REQ , "CERTIFICATE REQUEST"},
            {PEMTypes.PEM_X509_CRL , "X509 CRL"},
            {PEMTypes.PEM_EVP_PKEY , "ANY PRIVATE KEY"},
            {PEMTypes.PEM_PUBLIC , "PUBLIC KEY"},
            {PEMTypes.PEM_RSA , "RSA PRIVATE KEY"},
            {PEMTypes.PEM_RSA_PUBLIC , "RSA PUBLIC KEY"},
            {PEMTypes.PEM_DSA , "DSA PRIVATE KEY"},
            {PEMTypes.PEM_DSA_PUBLIC , "DSA PUBLIC KEY"},
            {PEMTypes.PEM_PKCS7 , "PKCS7"},
            {PEMTypes.PEM_PKCS7_SIGNED , "PKCS #7 SIGNED DATA"},
            {PEMTypes.PEM_PKCS8 , "ENCRYPTED PRIVATE KEY"},
            {PEMTypes.PEM_PKCS8INF , "PRIVATE KEY"},
            {PEMTypes.PEM_DHPARAMS , "DH PARAMETERS"},
            {PEMTypes.PEM_SSL_SESSION , "SSL SESSION PARAMETERS"},
            {PEMTypes.PEM_DSAPARAMS , "DSA PARAMETERS"},
            {PEMTypes.PEM_ECDSA_PUBLIC , "ECDSA PUBLIC KEY"},
            {PEMTypes.PEM_ECPARAMETERS , "EC PARAMETERS"},
            {PEMTypes.PEM_ECPRIVATEKEY , "EC PRIVATE KEY"},
            {PEMTypes.PEM_CMS , "CMS"},
            {PEMTypes.PEM_SSH2_PUBLIC , "SSH2 PUBLIC KEY"},
            {PEMTypes.UNKNOWN , "UNKNOWN"}
        };

        #endregion Helper
    }
}
