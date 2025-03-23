using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;

class Program
{
    static void Main(string[] args)
    {
        var arguments = ParseArguments(args);
        Execute(arguments);
    }

    private static Dictionary<string, string> ParseArguments(string[] args)
    {
        var arguments = new Dictionary<string, string>();
        foreach (string argument in args)
        {
            int idx = argument.IndexOf(':');
            if (idx > 0 && idx < argument.Length - 1)
            {
                string key = argument.Substring(0, idx).ToLower();
                string value = argument.Substring(idx + 1);
                arguments[key] = value;
            }
        }
        return arguments;
    }

    public static void Execute(Dictionary<string, string> arguments)
    {
        Console.WriteLine("\r\n[*] Action: Calculate Password Hash(es)\r\n");

        string user = "";
        string domain = "";
        string password = "";

        if (arguments.ContainsKey("/domain"))
        {
            domain = arguments["/domain"];
        }

        if (arguments.ContainsKey("/user"))
        {
            string[] parts = arguments["/user"].Split('\\');
            if (parts.Length == 2)
            {
                domain = parts[0];
                user = parts[1];
            }
            else
            {
                user = arguments["/user"];
            }
        }

        if (arguments.ContainsKey("/password"))
        {
            password = arguments["/password"];
        }
        else
        {
            Console.WriteLine("[X] /password:X must be supplied!");
            return;
        }
        Crypto.ComputeAllKerberosPasswordHashes(password, user, domain);
    }

    // Implement the Crypto class and ComputeAllKerberosPasswordHashes method
    public class Crypto
    {
        public static void ComputeAllKerberosPasswordHashes(string password, string userName = "", string domainName = "")
        {
            // use KerberosPasswordHash() to calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5 hashes for a given password

            Console.WriteLine("[*] Input password             : {0}", password);

            string salt = String.Format("{0}{1}", domainName.ToUpper(), userName);

            // special case for computer account salts
            if (userName.EndsWith("$"))
            {
                salt = String.Format("{0}host{1}.{2}", domainName.ToUpper(), userName.TrimEnd('$').ToLower(), domainName.ToLower());
            }

            if (!String.IsNullOrEmpty(userName) && !String.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("[*] Input username             : {0}", userName);
                Console.WriteLine("[*] Input domain               : {0}", domainName);
                Console.WriteLine("[*] Salt                       : {0}", salt);
            }

            string rc4Hash = KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, password);
            Console.WriteLine("[*]       rc4_hmac             : {0}", rc4Hash);

            if (String.IsNullOrEmpty(userName) || String.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("\r\n[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!");
            }
            else
            {
                string aes128Hash = KerberosPasswordHash(Interop.KERB_ETYPE.aes128_cts_hmac_sha1, password, salt);
                Console.WriteLine("[*]       aes128_cts_hmac_sha1 : {0}", aes128Hash);

                string aes256Hash = KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, password, salt);
                Console.WriteLine("[*]       aes256_cts_hmac_sha1 : {0}", aes256Hash);

                string desHash = KerberosPasswordHash(Interop.KERB_ETYPE.des_cbc_md5, String.Format("{0}{1}", password, salt), salt);
                Console.WriteLine("[*]       des_cbc_md5          : {0}", desHash);
            }

            Console.WriteLine();
        }

        public static string KerberosPasswordHash(Interop.KERB_ETYPE etype, string password, string salt = "", int count = 4096)
        {
            // use the internal KERB_ECRYPT HashPassword() function to calculate a password hash of a given etype
            // adapted from @gentilkiwi's Mimikatz "kerberos::hash" implementation

            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system for the hash type we want
            int status = Interop.CDLocateCSystem(etype, out pCSystemPtr);

            pCSystem = (Interop.KERB_ECRYPT)System.Runtime.InteropServices.Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "Error on CDLocateCSystem");

            // get the delegate for the password hash function
            Interop.KERB_ECRYPT_HashPassword pCSystemHashPassword = (Interop.KERB_ECRYPT_HashPassword)System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(pCSystem.HashPassword, typeof(Interop.KERB_ECRYPT_HashPassword));
            Interop.UNICODE_STRING passwordUnicode = new Interop.UNICODE_STRING(password);
            Interop.UNICODE_STRING saltUnicode = new Interop.UNICODE_STRING(salt);

            byte[] output = new byte[pCSystem.KeySize];

            int success = pCSystemHashPassword(passwordUnicode, saltUnicode, count, output);

            if (status != 0)
                throw new Win32Exception(status);

            return System.BitConverter.ToString(output).Replace("-", "");
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        public static byte[] KerberosChecksum(byte[] key, byte[] data, Interop.KERB_CHECKSUM_ALGORITHM cksumType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5, int keyUsage = Interop.KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT)
        {
            Interop.KERB_CHECKSUM pCheckSum;
            IntPtr pCheckSumPtr;
            int status = Interop.CDLocateCheckSum(cksumType, out pCheckSumPtr);
            pCheckSum = (Interop.KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr, typeof(Interop.KERB_CHECKSUM));
            if (status != 0)
            {
                throw new Win32Exception(status, "CDLocateCheckSum failed");
            }

            IntPtr Context;
            Interop.KERB_CHECKSUM_InitializeEx pCheckSumInitializeEx = (Interop.KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(Interop.KERB_CHECKSUM_InitializeEx));
            Interop.KERB_CHECKSUM_Sum pCheckSumSum = (Interop.KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(Interop.KERB_CHECKSUM_Sum));
            Interop.KERB_CHECKSUM_Finalize pCheckSumFinalize = (Interop.KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(Interop.KERB_CHECKSUM_Finalize));
            Interop.KERB_CHECKSUM_Finish pCheckSumFinish = (Interop.KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(Interop.KERB_CHECKSUM_Finish));

            // initialize the checksum
            // KERB_NON_KERB_CKSUM_SALT = 17
            int status2 = pCheckSumInitializeEx(key, key.Length, (int)keyUsage, out Context);
            if (status2 != 0)
                throw new Win32Exception(status2);

            // the output buffer for the checksum data
            byte[] checksumSrv = new byte[pCheckSum.Size];

            // actually checksum all the supplied data
            pCheckSumSum(Context, data.Length, data);

            // finish everything up
            pCheckSumFinalize(Context, checksumSrv);
            pCheckSumFinish(ref Context);

            return checksumSrv;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosDecrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output.Take(outputSize).ToArray();
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosEncrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }

        public static string FormDESHash(string stCypherHex, byte[] knownPlain)
        {
            byte[] IV = Helpers.StringToByteArray(stCypherHex.Substring(32, 16));
            byte[] firstBlock = Helpers.StringToByteArray(stCypherHex.Substring(48, 16));

            byte[] xoredIV = new byte[IV.Length];
            for (int i = 0; i < IV.Length; i++)
            {
                xoredIV[i] = (byte)(knownPlain[i] ^ IV[i]);
            }

            return string.Format("{0}:{1}", Helpers.ByteArrayToString(firstBlock), Helpers.ByteArrayToString(xoredIV));
        }
    }
}

public class Interop
{
    public const int KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT = 17;

    [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);

    [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);

    //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1753-L1767
    public delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
    public delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
    public delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
    public delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

    public delegate int KERB_ECRYPT_HashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int count, byte[] output);

    //https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1760-L1767
    public delegate int KERB_CHECKSUM_Initialize(int unk0, out IntPtr pContext);
    public delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int Size, byte[] Buffer);
    public delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] Buffer);
    public delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);
    public delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);

    // from https://tools.ietf.org/html/rfc3961
    public enum KERB_ETYPE : Int32
    {
        des_cbc_crc = 1,
        des_cbc_md4 = 2,
        des_cbc_md5 = 3,
        des3_cbc_md5 = 5,
        des3_cbc_sha1 = 7,
        dsaWithSHA1_CmsOID = 9,
        md5WithRSAEncryption_CmsOID = 10,
        sha1WithRSAEncryption_CmsOID = 11,
        rc2CBC_EnvOID = 12,
        rsaEncryption_EnvOID = 13,
        rsaES_OAEP_ENV_OID = 14,
        des_ede3_cbc_Env_OID = 15,
        des3_cbc_sha1_kd = 16,
        aes128_cts_hmac_sha1 = 17,
        aes256_cts_hmac_sha1 = 18,
        rc4_hmac = 23,
        rc4_hmac_exp = 24,
        subkey_keymaterial = 65,
        old_exp = -135
    }

    // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
    //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_ECRYPT
    {
        int Type0;
        public int BlockSize;
        int Type1;
        public int KeySize;
        public int Size;
        int unk2;
        int unk3;
        public IntPtr AlgName;
        public IntPtr Initialize;
        public IntPtr Encrypt;
        public IntPtr Decrypt;
        public IntPtr Finish;
        public IntPtr HashPassword;
        IntPtr RandomKey;
        IntPtr Control;
        IntPtr unk0_null;
        IntPtr unk1_null;
        IntPtr unk2_null;
    }

    public enum KERB_CHECKSUM_ALGORITHM
    {
        KERB_CHECKSUM_NONE = 0,
        KERB_CHECKSUM_RSA_MD4 = 2,
        KERB_CHECKSUM_RSA_MD5 = 7,
        KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
        KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
        KERB_CHECKSUM_DES_MAC = -133,
        KERB_CHECKSUM_HMAC_MD5 = -138,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CHECKSUM
    {
        public int Type;
        public int Size;
        public int Flag;
        public IntPtr Initialize;
        public IntPtr Sum;
        public IntPtr Finalize;
        public IntPtr Finish;
        public IntPtr InitializeEx;
        public IntPtr unk0_null;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

}

public class Helpers
{
    public static string ByteArrayToString(byte[] bytes)
    {
        char[] c = new char[bytes.Length * 2];
        int b;
        for (int i = 0; i < bytes.Length; i++)
        {
            b = bytes[i] >> 4;
            c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
            b = bytes[i] & 0xF;
            c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
        }
        return new string(c);
    }

    public static byte[] StringToByteArray(string hex)
    {
        // converts a rc4/AES/etc. string into a byte array representation

        if ((hex.Length % 16) != 0)
        {
            Console.WriteLine("\r\n[X] Hash must be 16, 32 or 64 characters in length\r\n");
            System.Environment.Exit(1);
        }

        // yes I know this inefficient
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

}