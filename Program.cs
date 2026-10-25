using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    // Khóa AES-256 có độ dài 32 byte
    private static byte[]? aesKey;

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        while (true)
        {
            Console.WriteLine("\n==================================");
            Console.WriteLine("       CHUONG TRINH MA HOA AES");
            Console.WriteLine("==================================");
            Console.WriteLine("1. Sinh khoa AES-256");
            Console.WriteLine("2. Luu khoa AES vao file");
            Console.WriteLine("3. Import khoa AES tu file");
            Console.WriteLine("4. Ma hoa van ban");
            Console.WriteLine("5. Giai ma van ban");
            Console.WriteLine("6. Ma hoa file");
            Console.WriteLine("7. Giai ma file");
            Console.WriteLine("8. So sanh hai file theo byte");
            Console.WriteLine("9. Thu nghiem: ma hoa, giai ma, do thoi gian");
            Console.WriteLine("0. Thoat");
            Console.WriteLine("----------------------------------");
            Console.Write("Nhap lua chon: ");

            string? choice = Console.ReadLine();

            try
            {
                switch (choice)
                {
                    case "1":
                        GenerateKey();
                        break;

                    case "2":
                        SaveKey();
                        break;

                    case "3":
                        LoadKey();
                        break;

                    case "4":
                        EncryptText();
                        break;

                    case "5":
                        DecryptText();
                        break;

                    case "6":
                        EncryptFileMenu();
                        break;

                    case "7":
                        DecryptFileMenu();
                        break;

                    case "8":
                        CompareFilesMenu();
                        break;

                    case "9":
                        RunExperiment();
                        break;

                    case "0":
                        Console.WriteLine("Da thoat chuong trinh.");
                        return;

                    default:
                        Console.WriteLine("Lua chon khong hop le!");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Da xay ra loi: " + ex.Message);
            }
        }
    }

    // 1. Sinh khoa AES-256
    static void GenerateKey()
    {
        using Aes aes = Aes.Create();

        aes.KeySize = 256;
        aes.GenerateKey();

        aesKey = aes.Key;

        Console.WriteLine("Da sinh khoa AES-256 thanh cong.");
        Console.WriteLine("Do dai khoa: " + aesKey.Length + " byte");
        Console.WriteLine("Khoa dang Hex:");
        Console.WriteLine(Convert.ToHexString(aesKey));
    }

    // 2. Luu khoa vao file
    static void SaveKey()
    {
        if (aesKey == null)
        {
            Console.WriteLine("Hay sinh hoac import khoa truoc.");
            return;
        }

        Console.Write("Nhap duong dan file luu khoa: ");
        string path = ReadPath();

        string? directory = Path.GetDirectoryName(
            Path.GetFullPath(path));

        if (directory != null)
            Directory.CreateDirectory(directory);

        File.WriteAllBytes(path, aesKey);

        Console.WriteLine("Da luu khoa vao: " + path);
    }

    // 3. Import khoa tu file
    static void LoadKey()
    {
        Console.Write("Nhap duong dan file khoa: ");
        string path = ReadPath();

        byte[] key = File.ReadAllBytes(path);

        if (key.Length != 32)
        {
            Console.WriteLine(
                "Khoa khong hop le. AES-256 can khoa 32 byte.");
            return;
        }

        aesKey = key;

        Console.WriteLine("Import khoa thanh cong.");
        Console.WriteLine("Do dai khoa: " + aesKey.Length + " byte");
    }

    // 4. Ma hoa van ban
    static void EncryptText()
    {
        if (!EnsureKey())
            return;

        Console.Write("Nhap van ban can ma hoa: ");
        string plainText = Console.ReadLine() ?? "";

        byte[] encrypted = EncryptTextBytes(plainText, aesKey!);

        string base64 = Convert.ToBase64String(encrypted);

        Console.WriteLine("\nKet qua ma hoa Base64:");
        Console.WriteLine(base64);

        Console.Write("Nhap file de luu ket qua (Enter de bo qua): ");
        string outputPath = Console.ReadLine() ?? "";

        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            File.WriteAllText(outputPath, base64, Encoding.UTF8);
            Console.WriteLine("Da luu ket qua vao: " + outputPath);
        }
    }

    // 5. Giai ma van ban
    static void DecryptText()
    {
        if (!EnsureKey())
            return;

        Console.Write("Nhap chuoi Base64 can giai ma: ");
        string base64 = Console.ReadLine() ?? "";

        byte[] encrypted = Convert.FromBase64String(base64);

        string plainText = DecryptTextBytes(encrypted, aesKey!);

        Console.WriteLine("\nVan ban sau khi giai ma:");
        Console.WriteLine(plainText);
    }

    // Ma hoa van ban bang AES-CBC
    static byte[] EncryptTextBytes(string plainText, byte[] key)
    {
        using Aes aes = Aes.Create();

        aes.KeySize = 256;
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using ICryptoTransform encryptor =
            aes.CreateEncryptor();

        using MemoryStream output = new MemoryStream();

        // 16 byte dau tien la IV
        output.Write(aes.IV, 0, aes.IV.Length);

        using (CryptoStream cryptoStream = new CryptoStream(
            output, encryptor, CryptoStreamMode.Write, true))
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);

            cryptoStream.Write(inputBytes, 0, inputBytes.Length);
        }

        return output.ToArray();
    }

    // Giai ma van ban bang AES-CBC
    static string DecryptTextBytes(byte[] encrypted, byte[] key)
    {
        if (encrypted.Length < 32 ||
            (encrypted.Length - 16) % 16 != 0)
        {
            throw new InvalidDataException(
                "Du lieu ma hoa khong hop le.");
        }

        byte[] iv = new byte[16];

        Array.Copy(encrypted, 0, iv, 0, 16);

        using Aes aes = Aes.Create();

        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using ICryptoTransform decryptor =
            aes.CreateDecryptor();

        using MemoryStream input = new MemoryStream(
            encrypted, 16, encrypted.Length - 16);

        using CryptoStream cryptoStream = new CryptoStream(
            input, decryptor, CryptoStreamMode.Read);

        using MemoryStream output = new MemoryStream();

        cryptoStream.CopyTo(output);

        return Encoding.UTF8.GetString(output.ToArray());
    }

    // 6. Ma hoa file
    static void EncryptFileMenu()
    {
        if (!EnsureKey())
            return;

        Console.Write("Nhap duong dan file nguon: ");
        string source = ReadPath();

        Console.Write("Nhap duong dan file ma hoa: ");
        string destination = ReadPath();

        if (SameFile(source, destination))
        {
            Console.WriteLine("File nguon va file dich phai khac nhau.");
            return;
        }

        if (File.Exists(destination))
        {
            Console.WriteLine("File dich da ton tai. Khong ghi de.");
            return;
        }

        Stopwatch sw = Stopwatch.StartNew();

        EncryptFile(source, destination, aesKey!);

        sw.Stop();

        Console.WriteLine("Ma hoa file thanh cong.");
        Console.WriteLine("Dung luong nguon: " +
            new FileInfo(source).Length + " byte");
        Console.WriteLine("Dung luong ma hoa: " +
            new FileInfo(destination).Length + " byte");
        Console.WriteLine("Thoi gian ma hoa: " +
            sw.Elapsed.TotalSeconds.ToString("F3") + " giay");
    }

    // Ma hoa file theo tung khoi, khong nap ca file vao RAM
    static void EncryptFile(
        string sourcePath,
        string destinationPath,
        byte[] key)
    {
        using Aes aes = Aes.Create();

        aes.KeySize = 256;
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using FileStream input = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);

        using FileStream output = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.SequentialScan);

        // Ghi IV vao dau file ma hoa
        output.Write(aes.IV, 0, aes.IV.Length);

        using ICryptoTransform encryptor =
            aes.CreateEncryptor();

        using (CryptoStream cryptoStream = new CryptoStream(
            output, encryptor, CryptoStreamMode.Write, true))
        {
            input.CopyTo(cryptoStream, 1024 * 1024);
        }
    }

    // 7. Giai ma file
    static void DecryptFileMenu()
    {
        if (!EnsureKey())
            return;

        Console.Write("Nhap duong dan file ma hoa: ");
        string source = ReadPath();

        Console.Write("Nhap duong dan file sau giai ma: ");
        string destination = ReadPath();

        if (SameFile(source, destination))
        {
            Console.WriteLine("File nguon va file dich phai khac nhau.");
            return;
        }

        if (File.Exists(destination))
        {
            Console.WriteLine("File dich da ton tai. Khong ghi de.");
            return;
        }

        Stopwatch sw = Stopwatch.StartNew();

        DecryptFile(source, destination, aesKey!);

        sw.Stop();

        Console.WriteLine("Giai ma file thanh cong.");
        Console.WriteLine("Thoi gian giai ma: " +
            sw.Elapsed.TotalSeconds.ToString("F3") + " giay");
    }

    // Giai ma file theo tung khoi
    static void DecryptFile(
        string sourcePath,
        string destinationPath,
        byte[] key)
    {
        using FileStream input = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);

        byte[] iv = new byte[16];

        int ivRead = 0;

        while (ivRead < iv.Length)
        {
            int read = input.Read(iv, ivRead, iv.Length - ivRead);

            if (read == 0)
                throw new InvalidDataException("File khong co IV hop le.");

            ivRead += read;
        }

        if (input.Length < 32 ||
            (input.Length - 16) % 16 != 0)
        {
            throw new InvalidDataException(
                "Kich thuoc file ma hoa khong hop le.");
        }

        using Aes aes = Aes.Create();

        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using ICryptoTransform decryptor =
            aes.CreateDecryptor();

        using FileStream output = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.SequentialScan);

        using CryptoStream cryptoStream = new CryptoStream(
            input, decryptor, CryptoStreamMode.Read);

        cryptoStream.CopyTo(output, 1024 * 1024);
    }

    // 8. So sanh hai file theo tung byte
    static void CompareFilesMenu()
    {
        Console.Write("Nhap duong dan file goc: ");
        string source = ReadPath();

        Console.Write("Nhap duong dan file can so sanh: ");
        string target = ReadPath();

        CompareFiles(source, target);
    }

    // So sanh file theo tung khoi byte
    static bool CompareFiles(string file1, string file2)
    {
        FileInfo info1 = new FileInfo(file1);
        FileInfo info2 = new FileInfo(file2);

        Console.WriteLine("\nDung luong file 1: " +
            info1.Length + " byte");

        Console.WriteLine("Dung luong file 2: " +
            info2.Length + " byte");

        if (info1.Length != info2.Length)
        {
            Console.WriteLine("KET QUA: HAI FILE KHAC NHAU.");
            return false;
        }

        const int bufferSize = 1024 * 1024;

        byte[] buffer1 = new byte[bufferSize];
        byte[] buffer2 = new byte[bufferSize];

        using FileStream fs1 = File.OpenRead(file1);
        using FileStream fs2 = File.OpenRead(file2);

        long comparedBytes = 0;

        while (true)
        {
            int read1 = fs1.Read(buffer1, 0, buffer1.Length);
            int read2 = fs2.Read(buffer2, 0, buffer2.Length);

            if (read1 != read2)
            {
                Console.WriteLine("KET QUA: HAI FILE KHAC NHAU.");
                return false;
            }

            if (read1 == 0)
                break;

            for (int i = 0; i < read1; i++)
            {
                if (buffer1[i] != buffer2[i])
                {
                    Console.WriteLine(
                        "KET QUA: HAI FILE KHAC NHAU.");
                    Console.WriteLine(
                        "Vi tri byte khac dau tien: " +
                        (comparedBytes + i));

                    return false;
                }
            }

            comparedBytes += read1;
        }

        Console.WriteLine("KET QUA: HAI FILE GIONG NHAU.");
        Console.WriteLine("Da so sanh: " + comparedBytes + " byte.");

        return true;
    }

    // 9. Thu nghiem va do thoi gian
    static void RunExperiment()
    {
        if (!EnsureKey())
            return;

        Console.Write("Nhap duong dan file nguon: ");
        string source = ReadPath();

        Console.Write("Nhap duong dan file ma hoa: ");
        string encrypted = ReadPath();

        Console.Write("Nhap duong dan file giai ma: ");
        string decrypted = ReadPath();

        if (SameFile(source, encrypted) ||
            SameFile(source, decrypted) ||
            SameFile(encrypted, decrypted))
        {
            Console.WriteLine(
                "Ba duong dan phai tro den ba file khac nhau.");
            return;
        }

        if (File.Exists(encrypted) || File.Exists(decrypted))
        {
            Console.WriteLine(
                "File dau ra da ton tai. Hay chon ten file moi.");
            return;
        }

        long sourceSize = new FileInfo(source).Length;

        Console.WriteLine("\nBAT DAU THU NGHIEM...");
        Console.WriteLine("Dung luong file nguon: " +
            sourceSize + " byte");

        Stopwatch encryptWatch = Stopwatch.StartNew();

        EncryptFile(source, encrypted, aesKey!);

        encryptWatch.Stop();

        Stopwatch decryptWatch = Stopwatch.StartNew();

        DecryptFile(encrypted, decrypted, aesKey!);

        decryptWatch.Stop();

        Console.WriteLine("\n===== KET QUA THU NGHIEM =====");

        Console.WriteLine("File nguon: " + sourceSize + " byte");

        Console.WriteLine("File ma hoa: " +
            new FileInfo(encrypted).Length + " byte");

        Console.WriteLine("File giai ma: " +
            new FileInfo(decrypted).Length + " byte");

        Console.WriteLine("Thoi gian ma hoa: " +
            encryptWatch.Elapsed.TotalSeconds.ToString("F3") +
            " giay");

        Console.WriteLine("Thoi gian giai ma: " +
            decryptWatch.Elapsed.TotalSeconds.ToString("F3") +
            " giay");

        bool identical = CompareFiles(source, decrypted);

        double encryptSpeed =
            encryptWatch.Elapsed.TotalSeconds > 0
            ? sourceSize / 1024.0 / 1024.0 /
              encryptWatch.Elapsed.TotalSeconds
            : 0;

        double decryptSpeed =
            decryptWatch.Elapsed.TotalSeconds > 0
            ? sourceSize / 1024.0 / 1024.0 /
              decryptWatch.Elapsed.TotalSeconds
            : 0;

        Console.WriteLine("Toc do ma hoa: " +
            encryptSpeed.ToString("F2") + " MiB/s");

        Console.WriteLine("Toc do giai ma: " +
            decryptSpeed.ToString("F2") + " MiB/s");

        Console.WriteLine("Ket luan so sanh: " +
            (identical
                ? "FILE GIAI MA GIONG HOAN TOAN FILE GOC."
                : "FILE GIAI MA KHAC FILE GOC."));

        Console.WriteLine("\nLuu y: Thoi gian tren bao gom doc/ghi file.");
        Console.WriteLine("Hieu nang co the thay doi theo o dia, CPU,");
        Console.WriteLine("bo nho dem va cac ung dung dang chay.");
    }

    // Kiem tra da co khoa hay chua
    static bool EnsureKey()
    {
        if (aesKey == null || aesKey.Length != 32)
        {
            Console.WriteLine(
                "Chua co khoa AES-256. Hay chon 1 hoac 3 truoc.");
            return false;
        }

        return true;
    }

    // Doc duong dan va loai bo dau ngoac kep neu co
    static string ReadPath()
    {
        string path = Console.ReadLine()?.Trim() ?? "";

        if (path.Length >= 2 &&
            path.StartsWith("\"") &&
            path.EndsWith("\""))
        {
            path = path[1..^1];
        }

        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Duong dan khong duoc de trong.");

        return path;
    }

    // Kiem tra hai duong dan co cung tro den mot file khong
    static bool SameFile(string path1, string path2)
    {
        string full1 = Path.GetFullPath(path1);
        string full2 = Path.GetFullPath(path2);

        return string.Equals(
            full1,
            full2,
            StringComparison.OrdinalIgnoreCase);
    }
}