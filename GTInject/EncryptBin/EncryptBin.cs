﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace GTInject.EncryptBin
{
    internal class EncryptBin
    {

        public static void EncryptShellcode(string binPath, string xorkey)
        {

            //============ 
            //Input file selection - specify the bin file that we should encrypt
            byte[] bytes = System.IO.File.ReadAllBytes(binPath);
            StringBuilder programOutput = new StringBuilder();
            programOutput.Append("Bytes size is : " + bytes.Length);
            programOutput.Append(Environment.NewLine);

            programOutput.Append("absolute path of file to xor is " + binPath);
            programOutput.Append(Environment.NewLine);
            String inputPath = binPath;
            String key = xorkey;
            string b64key = Convert.ToBase64String(Encoding.UTF8.GetBytes(key));  //Encoding.UTF8.GetString(Convert.ToBase64String(key));
            programOutput.Append("XOR key statically entered as " + key);
            programOutput.Append(Environment.NewLine);
            programOutput.Append("XOR key in b64 is : " + b64key);
            programOutput.Append(Environment.NewLine);

            // Figure out the output bin
            var filenameext= Path.GetExtension(binPath);
            var filename = Path.GetFileNameWithoutExtension(binPath);
            //var filename = binPath.Split(".bin", StringSplitOptions.None)[0];  //binPath.Split(".bin")[0];
            var outputBinFile = filename + "-xord.bin";
            programOutput.Append("absolute path to write output to is " + outputBinFile);
            programOutput.Append(Environment.NewLine);

            String outputPath = outputBinFile;
            byte[] payload = File.ReadAllBytes(inputPath);
            byte[] stuff = XOR(payload, key);
            File.WriteAllBytes(outputPath, stuff);
            programOutput.AppendFormat("successfully XOR'd {0}! \n Data written to {1}", inputPath, outputPath);
            programOutput.Append(Environment.NewLine);


            //Bin file was xord and stored, lets read it convert to other formats
            byte[] Xord = File.ReadAllBytes(outputPath);

            StringBuilder xor64return = PrintXordCSharpFormat(Xord);
            StringBuilder xorcshreturn = PrintXordCFormat(Xord);
            StringBuilder xorcreturn = PrintXordBase64String(Xord);

            programOutput.Append(xor64return.ToString());
            programOutput.Append(xorcshreturn.ToString());
            programOutput.Append(xorcreturn.ToString());

            var outputTextFile = outputPath.Replace(".bin", ".txt");
            string b64outputfilename = outputPath.Replace(".bin", ".b64");
            var outputBase64Payload = PrintXordB64ForFile(Xord).ToString();
            File.WriteAllText(outputTextFile, programOutput.ToString());
            File.WriteAllText(b64outputfilename, outputBase64Payload.ToString());
            Console.WriteLine("[+] Writing all encrypted data to files in the current directory\n");

        }

        private static StringBuilder PrintXordBase64String(byte[] Xord)
        {
            var xordb64 = Convert.ToBase64String(Xord);
            StringBuilder xor64string = new StringBuilder();
            xor64string.Append("Base64 XORD payload : ");
            xor64string.Append(Environment.NewLine);
            xor64string.Append(xordb64.ToString());
            xor64string.Append(Environment.NewLine);
            return xor64string;
        }


        private static StringBuilder PrintXordB64ForFile(byte[] Xord)
        {
            var xordb64 = Convert.ToBase64String(Xord);
            StringBuilder xor64string = new StringBuilder();
            xor64string.Append(xordb64.ToString());
            return xor64string;
        }
        private static StringBuilder PrintXordCSharpFormat(byte[] bytes)
        {
            StringBuilder printxord = new StringBuilder(bytes.Length * 2);
            foreach (byte a in bytes)
            {
                printxord.AppendFormat("0x{0:X2}, ", a);
            }

            StringBuilder xorcsh = new StringBuilder();
            xorcsh.Append("CSharp format : ");
            xorcsh.Append(Environment.NewLine);
            xorcsh.Append(printxord);
            xorcsh.Append(Environment.NewLine);
            return xorcsh;
        }

        private static StringBuilder PrintXordCFormat(byte[] bytes)
        {
            var ccharcounter = 0;
            StringBuilder print4c = new StringBuilder(bytes.Length * 2);
            print4c.AppendFormat("\"");
            foreach (byte c in bytes)
            {
                print4c.AppendFormat("\\x{0:X2}", c);
                ccharcounter++;

                if (ccharcounter % 15 == 0)
                {
                    print4c.AppendFormat("\"");
                    print4c.AppendFormat("{0}", Environment.NewLine);
                    print4c.AppendFormat("\"");
                }
            }
            StringBuilder xorcstring = new StringBuilder();
            xorcstring.Append("C Format: ");
            xorcstring.Append(Environment.NewLine);
            xorcstring.Append(print4c);
            xorcstring.Append(Environment.NewLine);
            return xorcstring;
        }

        public static byte[] XOR(byte[] payload, string XORKey)
        {
            byte[] xorStuff = new byte[payload.Length];
            char[] bXORKey = XORKey.ToCharArray();
            for (int i = 0; i < payload.Length; i++)
            {
                xorStuff[i] = (byte)(payload[i] ^ bXORKey[i % bXORKey.Length]);
            }
            return xorStuff;
        }
    }
}
