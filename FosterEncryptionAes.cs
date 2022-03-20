using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace LibFoster.Modules
{
    /// <summary>
    /// AES Encryption for Foster.
    /// </summary>
    public class FosterEncryptionAes : FosterEncryptionBase
    {
        /// <inheritdoc />
        public override string EncryptionName => "aes";

        /// <inheritdoc />
        public override Stream GenerateEncryptStream(Stream inStream, byte[] arguments, byte[] password)
        {
            var aes = Aes.Create();
            aes.Key = password;
            byte[] iv = new byte[arguments.Length - sizeof(int)];
            for (int i = 1; i < arguments.Length; i++)
            {
                iv[i - 1] = arguments[i];
            }
            aes.IV = iv;
            switch (arguments[0])
            {
                default:
                case 0:
                    aes.Mode = CipherMode.CBC;
                    break;

                case 1:
                    aes.Mode = CipherMode.ECB;
                    break;

                case 2:
                    aes.Mode = CipherMode.CFB;
                    break;

                case 3:
                    aes.Mode = CipherMode.OFB;
                    break;

                case 4:
                    aes.Mode = CipherMode.CTS;
                    break;
            }
            var encryptor = aes.CreateEncryptor();
            return new CryptoStream(inStream, encryptor, CryptoStreamMode.Write);
        }

        /// <inheritdoc />
        public override Stream GenerateDecryptStream(Stream inStream, byte[] arguments, byte[] password)
        {
            var aes = Aes.Create();
            aes.Key = password;
            byte[] iv = new byte[arguments.Length - sizeof(int)];
            for (int i = 1; i < arguments.Length; i++)
            {
                iv[i - 1] = arguments[i];
            }
            aes.IV = iv;
            switch (arguments[0])
            {
                default:
                case 0:
                    aes.Mode = CipherMode.CBC;
                    break;

                case 1:
                    aes.Mode = CipherMode.ECB;
                    break;

                case 2:
                    aes.Mode = CipherMode.CFB;
                    break;

                case 3:
                    aes.Mode = CipherMode.OFB;
                    break;

                case 4:
                    aes.Mode = CipherMode.CTS;
                    break;
            }
            var encryptor = aes.CreateEncryptor();
            return new CryptoStream(inStream, encryptor, CryptoStreamMode.Read);
        }
    }
}