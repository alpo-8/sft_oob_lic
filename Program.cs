using System;
using System.Linq;
using System.Security.Cryptography;

namespace sft_oob_lic
{
    class Program
    {
        // IPMI MAC
        static byte[] _bmcMac = { 0x00, 0x25, 0x90, 0x9e, 0xd6, 0x1d };

        // SUPERMICRO VARIABLES
        static readonly byte[] oobPKey = new byte[] { 0x85, 0x44, 0xe3, 0xb4, 0x7e, 0xca, 0x58, 0xf9, 0x58, 0x30, 0x43, 0xf8 };
        static readonly byte[] hsdcKey = new byte[] { 0x39, 0xcb, 0x2a, 0x1a, 0x3d, 0x74, 0x8f, 0xf1, 0xde, 0xe4, 0x6b, 0x87 };

        public static void Main()
            => Console.WriteLine($"SFT-OOB-LIC Key:\t{Hash12(oobPKey)}\nSFT-DCMS-Single:\t{Hash12(hsdcKey)}");

        static string Hash12(byte[] pKey)
            => string.Concat(new HMACSHA1(pKey).ComputeHash(_bmcMac).Take(0xc)
                             .Select((b, i) => $"{b:x2}{(i < 0xb && i % 2 != 0 ? "-" : "")}"));
    }
}
