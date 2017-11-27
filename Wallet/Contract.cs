using System;
using Newtonsoft.Json;

namespace Wallet
{
    public class Contract
    {
        /// <summary>
        /// The script code of the contract. 
        /// This field can be null if the contract has been deployed to the blockchain. 
        /// </summary>
        [JsonProperty("script")]
        public string Script { get; set; }

        /// <summary>
        /// An array of Parameter objects which describe the details of each parameter in the contract function.
        /// </summary>
        [JsonProperty("parameters")]
        public Parameter[] Parameters { get; set; }

        /// <summary>
        /// An array of Parameter objects which describe the details of each parameter in the contract function.
        /// For more information about Parameter object, see the descriptions in NEP-3: <see href="https://github.com/neo-project/proposals/pull/12">NeoContract ABI</see>
        /// </summary>
        [JsonProperty("deployed")]
        public bool Deployed { get; set; }

        public Contract(string script, Parameter[] parameters)
        {
            if (string.IsNullOrEmpty(script)) throw new ArgumentNullException(nameof(script));
            if (parameters.Length <= 0) throw new ArgumentNullException(nameof(parameters));

            Script = script;
            Parameters = parameters;
            Deployed = false;
        }
    }
}