using System;
using System.Collections.Generic;
using System.Text;

namespace Wallet
{
    public class Contract
    {
        public string Script { get; set; }
        public Parameter[] Parameters { get; set; }
        public bool Deployed { get; set; }
    }
}
