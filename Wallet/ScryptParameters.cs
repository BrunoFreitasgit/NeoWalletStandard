using System;

namespace Wallet
{
    public class ScryptParameters
    {
        public int N { get; }
        public int R { get; }
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
