using System;

namespace FFF.Security.RSA
{
    [Serializable]
    public class RSAKeyInfo
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}
