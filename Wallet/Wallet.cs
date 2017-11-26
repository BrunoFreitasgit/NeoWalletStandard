using System;
using System.Collections.Generic;
using System.Linq;
using Neo.Wallets;
using Wallet.Crypto;

namespace Wallet
{
    public class Wallet
    {
        public string Name { get; set; }                                        // name is a label that the user has made to the wallet file.
        public ScryptParameters Scrypt { get; set; }                            // scrypt is a ScryptParameters object which describe the parameters of SCrypt algorithm used for encrypting and decrypting the private keys in the wallet.
        public IList<Account> Accounts { get; set; }                            // accounts is an array of Account objects which describe the details of each account in the wallet.
        public object Extra { get; set; }                                       // extra is an object that is defined by the implementor of the client for storing extra data.This field can be null.

        public Wallet(string name, ScryptParameters scryptParameters = null, object extra = null)
        {
            Name = name ?? "default";
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
            Account newAccount = Account.Create(accountLabel, isDefault, isLock, passphrase, Scrypt); //todo add validation           
            return newAccount;
        }

        private Account AddWatchOnlyAccount(string address, string accountLabel)
        {
            return Account.CreateWatchOnly(address, accountLabel);
        }
    }
}
