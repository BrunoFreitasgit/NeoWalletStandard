using System;
using Newtonsoft.Json;

namespace Wallet
{
    public class ScryptParameters
    {
        /// <summary>
        /// A parameter that defines the CPU/memory cost. Must be a value 2^N. 
        /// </summary>
        [JsonProperty("n")]
        public int N { get; }

        /// <summary>
        /// A tuning parameter. 
        /// </summary>
        [JsonProperty("r")]
        public int R { get; }

        /// <summary>
        /// A tuning parameter (parallelization parameter).
        /// A large value of p can increase computational cost of SCrypt without increasing the memory usage. 
        /// </summary>
        [JsonProperty("p")]
        public int P { get; }

        public ScryptParameters(int r = 8, int p = 8, int n = 16384)
        {
            if (r <= 0) throw new ArgumentOutOfRangeException(nameof(r));
            if (p <= 0) throw new ArgumentOutOfRangeException(nameof(p));
            if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));

            N = n;
            P = p;
            R = r;
        }
    }
}