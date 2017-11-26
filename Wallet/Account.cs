using System;
using System.Security.Cryptography;
using Neo;
using Neo.Core;
using Neo.Cryptography;
using Neo.VM;
using Neo.Wallets;
using ECPoint = Neo.Cryptography.ECC.ECPoint;


namespace Wallet
{
    public class Account
    {
        public string Address { get; }         // is the base58 encoded address of the account. AQLASLtT6pWbThcSCYU1biVqhMnzhTgLFq
        public string Label { get; set; }        // is a label that the user has made to the account. 
        public bool IsDefault { get; set; }                // indicates whether the account is the default change account. 
        public bool IsLock { get; set; }                   // indicates whether the account is locked by user. The client shouldn't spend the funds in a locked account. 
        public string Key { get; private set; }                                  // is the private key of the account in the NEP-2 format.This field can be null (for watch-only address or non-standard address). 6PYWB8m1bCnu5bQkRUKAwbZp2BHNvQ3BQRLbpLdTuizpyLkQPSZbtZfoxx
        public Contract Contract { get; set; }         // is a Contract object which describes the details of the contract.
        public object Extra { get; set; } = null;                   // is an object that is defined by the implementor of the client for storing extra data. This field can be null

        protected Account(string address, string label, bool isDefault, bool isLock, string key)
        {
            Address = address;
            Label = label;
            IsDefault = isDefault;
            IsLock = isLock;
            Key = key;
        }

        protected Account(string address, string label)
        {
            Address = address;
            Label = label;
            IsDefault = false;
            IsLock = true;
            Key = string.Empty;
            Contract = null;
            Extra = null;
        }

        public static Account Create(string label, bool isDefault, bool isLock, string passphrase, ScryptParameters scryptParameters)
        {
            var keys = CreateKey();
            UInt160 scriptHash = CreateSignatureRedeemScript(keys.PublicKey).ToScriptHash();
            string address = Neo.Wallets.Wallet.ToAddress(scriptHash);
            string nepKey = Crypto.Nep2.EncryptKey(passphrase, keys, scryptParameters);
            Account createdAccount = new Account(address, label, isDefault, isLock, nepKey)
            {
                Contract = new Contract
                {
                    Deployed = false,
                    Parameters = new[]
                    {
                        new Parameter("VerificationContract", ParameterType.Signature)
                    },
                    Script = scriptHash.ToString()
                }
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
