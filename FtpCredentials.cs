using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace AwsEc2SecurityGroups;

public class FtpCredentials(IDataProtectionProvider dataProtectionProvider)
{
    public async Task<string?> GetPasswordAsync()
    {
        var dataProtector = dataProtectionProvider.CreateProtector("AwsEc2SecurityGroups");

        if (File.Exists(PasswordFile))
            return dataProtector.Unprotect(await File.ReadAllTextAsync(PasswordFile));

        Console.Write("FTP password: ");
        var password = ReadConsolePassword();
        if (string.IsNullOrWhiteSpace(password))
            return null;

        await File.WriteAllTextAsync(PasswordFile, dataProtector.Protect(password));
        return password;
    }

    private static string ReadConsolePassword()
    {
        ConsoleKeyInfo key;
        StringBuilder enteredPasswordValue = new();
        while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
        {
            enteredPasswordValue.Append(key.KeyChar);
            Console.Write('*');
        }
        Console.WriteLine();
        return enteredPasswordValue.ToString();
    }

    public void Clear()
    {
        FileInfo file = new(PasswordFile);
        if (file.Exists)
        {
            Console.WriteLine("Saved credentials deleted");
            file.Delete();
            return;
        }

        Console.WriteLine("No saved credentials exist, nothing to do");
    }

    private static string PasswordFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AwsEc2SecurityGroups-Keys",
        "ftp.txt");
}
