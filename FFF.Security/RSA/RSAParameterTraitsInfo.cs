using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace FFF.Security.RSA
{
    /// <summary>
    /// Represents information about RSA key parameters, particularly the sizes of various components
    /// of an RSA key, based on the modulus length. This class is useful for determining the appropriate
    /// byte sizes of RSA key components for different key lengths. It is serializable for easy storage
    /// or transmission.
    /// </summary>
    [Serializable]
    public class RSAParameterTraitsInfo
    {
        /// <summary>
        /// A static dictionary mapping standard RSA key sizes in bits to their corresponding byte sizes.
        /// This helps in determining the size of various RSA key components based on the overall key size.
        /// </summary>
        private static readonly Dictionary<int, int> KeySizes = new Dictionary<int, int>
    {
        { 512, 0x40 },   // 512 bits -> 64 bytes
        { 1024, 0x80 },  // 1024 bits -> 128 bytes
        { 2048, 0x100 }, // 2048 bits -> 256 bytes
        { 4096, 0x200 }  // 4096 bits -> 512 bytes
    };

        // Properties for storing sizes of various RSA key components. Initialized to -1 to indicate an uninitialized state.
        public int SizeMod { get; private set; } = -1;  // Size of the modulus (n)
        public int SizeExp { get; private set; } = -1;  // Size of the exponent (e, d)
        public int SizeD { get; private set; } = -1;    // Size of D
        public int SizeP { get; private set; } = -1;    // Size of P
        public int SizeQ { get; private set; } = -1;    // Size of Q
        public int SizeDP { get; private set; } = -1;   // Size of DP
        public int SizeDQ { get; private set; } = -1;   // Size of DQ
        public int SizeInvQ { get; private set; } = -1; // Size of Inverse Q

        /// <summary>
        /// Constructor that initializes the RSAParameterTraitsInfo based on a given modulus length.
        /// It calculates the nearest upper power of 2 for the modulus length to handle non-standard sizes.
        /// </summary>
        /// <param name="modulusLengthInBits">The length of the RSA key modulus in bits.</param>
        public RSAParameterTraitsInfo(int modulusLengthInBits)
        {
            // Calculate the nearest upper power of 2 for non-standard modulus lengths.
            int assumedLength = (int)Math.Pow(2, Math.Ceiling(Math.Log(modulusLengthInBits, 2)));

            // Lookup and assign the sizes for RSA key components based on the calculated key size.
            if (KeySizes.TryGetValue(assumedLength, out int size))
            {
                SizeMod = size;
                SizeExp = -1; // Size of the exponent is intentionally not set.
                SizeD = size;
                SizeP = size / 2;
                SizeQ = size / 2;
                SizeDP = size / 2;
                SizeDQ = size / 2;
                SizeInvQ = size / 2;
            }
            else
            {
                // Handle cases where the key size is unknown, potentially through logging or exceptions.
                Debug.Assert(false, "Unknown key size encountered in RSAParameterTraitsInfo.");
            }
        }
    }
}

