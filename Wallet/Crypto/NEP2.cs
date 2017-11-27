using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Neo;
using Neo.Core;
using Neo.Cryptography;
using Neo.Wallets;
using ECCurve = Neo.Cryptography.ECC.ECCurve;
using ECPoint = Neo.Cryptography.ECC.ECPoint;

namespace Wallet.Crypto
{
    public static class Nep2
    {
        /// <summary>
        /// Decrypts a NEP2 key using a passphrase and the ScryptParameters, returning a private key
        /// </summary>
        /// <param name="nep2"></param>
        /// <param name="passphrase"></param>
        /// <param name="scryptParameters"></param>
        /// <returns>private key</returns>
        public static byte[] DecryptKey(string nep2, string passphrase, ScryptParameters scryptParameters)
        {
            if (nep2 == null) throw new ArgumentNullException(nameof(nep2));
            if (passphrase == null) throw new ArgumentNullException(nameof(passphrase));
            byte[] data = nep2.Base58CheckDecode();
            if (data.Length != 39 || data[0] != 0x01 || data[1] != 0x42 || data[2] != 0xe0)
                throw new FormatException();
            byte[] addresshash = new byte[4];
            Buffer.BlockCopy(data, 3, addresshash, 0, 4);
            byte[] derivedkey = SCrypt.DeriveKey(Encoding.UTF8.GetBytes(passphrase), addresshash, scryptParameters.N, scryptParameters.R, scryptParameters.P, 64);
            byte[] derivedhalf1 = derivedkey.Take(32).ToArray();
            byte[] derivedhalf2 = derivedkey.Skip(32).ToArray();
            byte[] encryptedkey = new byte[32];
            Buffer.BlockCopy(data, 7, encryptedkey, 0, 32);
            byte[] prikey = Xor(encryptedkey.Aes256Decrypt(derivedhalf2), derivedhalf1);
            ECPoint pubkey = ECCurve.Secp256r1.G * prikey;
            UInt160 scriptHash = Neo.SmartContract.Contract.CreateSignatureRedeemScript(pubkey).ToScriptHash();
            string address = Wallet.ToAddress(scriptHash);
            if (!Encoding.ASCII.GetBytes(address).Sha256().Sha256().Take(4).SequenceEqual(addresshash))
                throw new FormatException();
            return prikey;
        }

        /// <summary>
        /// Encrypts a private key using a passphrase and the ScryptParameters, returning the NEP2 key in string format
        /// </summary>
        /// <param name="passphrase"></param>
        /// <param name="keyPair"></param>
        /// <param name="scryptParameters"></param>
        /// <returns>NEP2</returns>
        public static string EncryptKey(string passphrase, KeyPair keyPair, ScryptParameters scryptParameters)
        {
            UInt160 scriptHash = Neo.SmartContract.Contract.CreateSignatureRedeemScript(keyPair.PublicKey).ToScriptHash();
            string address = Wallet.ToAddress(scriptHash);
            byte[] addresshash = Encoding.ASCII.GetBytes(address).Sha256().Sha256().Take(4).ToArray();
            byte[] derivedkey = SCrypt.DeriveKey(Encoding.UTF8.GetBytes(passphrase), addresshash, scryptParameters.N, scryptParameters.R, scryptParameters.P, 64);
            byte[] derivedhalf1 = derivedkey.Take(32).ToArray();
            byte[] derivedhalf2 = derivedkey.Skip(32).ToArray();
            byte[] encryptedkey = Xor(keyPair.PrivateKey, derivedhalf1).Aes256Encrypt(derivedhalf2);
            byte[] buffer = new byte[39];
            buffer[0] = 0x01;
            buffer[1] = 0x42;
            buffer[2] = 0xe0;
            Buffer.BlockCopy(addresshash, 0, buffer, 3, addresshash.Length);
            Buffer.BlockCopy(encryptedkey, 0, buffer, 7, encryptedkey.Length);
            return buffer.Base58CheckEncode();
        }

        internal static byte[] Xor(byte[] x, byte[] y)
        {
            if (x.Length != y.Length) throw new ArgumentException();
            return x.Zip(y, (a, b) => (byte)(a ^ b)).ToArray();
        }

        internal static byte[] Aes256Encrypt(this byte[] block, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(block, 0, block.Length);
                }
            }
        }
    }
}
