using System;
using System.Collections.Generic;
using System.Linq;
using Neo;
using Neo.Wallets;
using Newtonsoft.Json;
using Wallet.Crypto;

namespace Wallet
{
    public class Wallet
    {
        /// <summary>
        /// A label that the user has made to the wallet file
        /// </summary>
        [JsonProperty("name")]
        public string Name { get; set; }

        /// <summary>
        /// Is currently fixed at 1.0 and will be used for functional upgrades in the future. 
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; }

        /// <summary>
        /// Object which describe the parameters of SCrypt algorithm used for encrypting and decrypting the private keys in the wallet. 
        /// </summary>
        [JsonProperty("scrypt")]
        public ScryptParameters Scrypt { get; set; }

        /// <summary>
        /// An array of Account objects which describe the details of each account in the wallet.
        /// </summary>
        [JsonProperty("accounts")]
        public IList<Account> Accounts { get; set; }

        /// <summary>
        /// An object that is defined by the implementor of the client for storing extra data.This field can be null.
        /// </summary>
        [JsonProperty("extra")]
        public object Extra { get; set; }

        public Wallet(string name, ScryptParameters scryptParameters = null, object extra = null)
        {
            Name = name ?? "default";
            Version = "1.0";
            Scrypt = scryptParameters ?? new ScryptParameters();
            Accounts = new List<Account>();
            Extra = extra ?? null;
        }

        public bool AddNewAccount(string accountLabel, bool isDefault, bool isLock, string passphrase)
        {
            Account newAccount = CreateNewAccount(accountLabel, isDefault, isLock, passphrase);
            if (Accounts.Any(p => p.Address == newAccount.Address))
            {
                return false;
            }
            Accounts.Add(newAccount);
            return true;
        }

        public bool DeleteAccount(string accountLabel)
        {
            var accountToDelete = Accounts.Single(p => p.Label == accountLabel);
            return accountToDelete != null && Accounts.Remove(accountToDelete);
        }

        public static KeyPair GetKeysFromNep2(string nep2, string passphrase, ScryptParameters scryptParameters)
        {
            byte[] privateKey = Nep2.DecryptKey(nep2, passphrase, scryptParameters);
            KeyPair key = new KeyPair(privateKey);
            Array.Clear(privateKey, 0, privateKey.Length);
            return key;
        }

        private Account CreateNewAccount(string accountLabel, bool isDefault, bool isLock, string passphrase)
        {
            Account newAccount =
                Account.Create(accountLabel, isDefault, isLock, passphrase, Scrypt); //todo add validation           
            return newAccount;
        }

        private Account AddWatchOnlyAccount(string address, string accountLabel)
        {
            return Account.CreateWatchOnly(address, accountLabel);
        }

        public static string ToAddress(UInt160 scriptHash)
        {
            byte[] data = new byte[21];
            data[0] = AddressVersion;
            Buffer.BlockCopy(scriptHash.ToArray(), 0, data, 1, 20);
            return data.Base58CheckEncode();
        }

        public static UInt160 ToScriptHash(string address)
        {
            byte[] data = address.Base58CheckDecode();
            if (data.Length != 21)
                throw new FormatException();
            if (data[0] != AddressVersion)
                throw new FormatException();
            return new UInt160(data.Skip(1).ToArray());
        }

        public static byte AddressVersion { get; } = byte.Parse("23");
    }
}