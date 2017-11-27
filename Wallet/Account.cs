using System;
using System.Security.Cryptography;
using Neo;
using Neo.Core;
using Neo.Cryptography;
using Neo.VM;
using Neo.Wallets;
using Newtonsoft.Json;
using ECPoint = Neo.Cryptography.ECC.ECPoint;

namespace Wallet
{
    public class Account
    {
        /// <summary>
        /// The base58 encoded address of the account 
        /// e.g. AQLASLtT6pWbThcSCYU1biVqhMnzhTgLFq
        /// </summary>
        [JsonProperty("address")]
        public string Address { get; }

        /// <summary>
        /// Label that the user has made to the account. 
        /// </summary>
        [JsonProperty("label")]
        public string Label { get; set; }

        /// <summary>
        /// Indicates whether the account is the default change account.
        /// </summary>
        [JsonProperty("isDefault")]
        public bool IsDefault { get; set; }

        /// <summary>
        /// Indicates whether the account is locked by user. The client shouldn't spend the funds in a locked account. 
        /// </summary>
        [JsonProperty("lock")]
        public bool IsLock { get; set; }

        /// <summary>
        /// The private key of the account in the NEP-2 format. This field can be null (for watch-only address or non-standard address). 
        /// e.g. 6PYWB8m1bCnu5bQkRUKAwbZp2BHNvQ3BQRLbpLdTuizpyLkQPSZbtZfoxx
        /// </summary>
        [JsonProperty("key")]
        public string Key { get; private set; }

        /// <summary>
        /// Contract object which describes the details of the contract.
        /// </summary>
        [JsonProperty("contract")]
        public Contract Contract { get; set; }

        /// <summary>
        /// An object that is defined by the implementor of the client for storing extra data. This field can be null
        /// </summary>
        [JsonProperty("extra")]
        public object Extra { get; set; }

        protected Account(string address, string label, bool isDefault, bool isLock, string key)
        {
            Address = address;
            Label = label;
            IsDefault = isDefault;
            IsLock = isLock;
            Key = key;
        }

        protected Account(string address, string label, object extra = null)
        {
            Address = address;
            Label = label;
            IsDefault = false;
            IsLock = true;
            Key = string.Empty;
            Contract = null;
            Extra = extra;
        }

        public static Account Create(string label, bool isDefault, bool isLock, string passphrase,
            ScryptParameters scryptParameters)
        {
            var keys = CreateKey();
            UInt160 scriptHash = CreateSignatureRedeemScript(keys.PublicKey).ToScriptHash();
            string address = Wallet.ToAddress(scriptHash);
            string nepKey = Crypto.Nep2.EncryptKey(passphrase, keys, scryptParameters);
            Account createdAccount = new Account(address, label, isDefault, isLock, nepKey)
            {
                Contract = new Contract(scriptHash.ToString(), new[] //testing
                {
                    new Parameter("operation", ParameterType.String),
                    new Parameter("args", ParameterType.Array)
                })

            };
            return createdAccount;
        }

        public static Account CreateWatchOnly(string address, string label)
        {
            return new Account(address, label);
        }

        private static KeyPair CreateKey()
        {
            byte[] privateKey = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateKey);
            }
            KeyPair key = CreateKey(privateKey);
            Array.Clear(privateKey, 0, privateKey.Length);
            return key;
        }

        private static KeyPair CreateKey(byte[] privateKey)
        {
            return new KeyPair(privateKey);
        }

        public static byte[] GetPrivateKeyFromWif(string wif)
        {
            if (wif == null) throw new ArgumentNullException();
            byte[] data = wif.Base58CheckDecode();
            if (data.Length != 34 || data[0] != 0x80 || data[33] != 0x01)
                throw new FormatException();
            byte[] privateKey = new byte[32];
            Buffer.BlockCopy(data, 1, privateKey, 0, privateKey.Length);
            Array.Clear(data, 0, data.Length);
            return privateKey;
        }

        public static byte[] CreateSignatureRedeemScript(ECPoint publicKey)
        {
            using (ScriptBuilder sb = new ScriptBuilder())
            {
                sb.EmitPush(publicKey.EncodePoint(true));
                sb.Emit(OpCode.CHECKSIG);
                return sb.ToArray();
            }
        }
    }
}