using FluentFTP;

namespace AwsEc2SecurityGroups;

public class FtpCommand(FtpCredentials ftpCredentials)
{
    public void ClearFtpCredentials() => ftpCredentials.Clear();

    public async Task ToggleOfflineAsync(string sitePath, bool setOffline)
    {
        var ftpPassword = await ftpCredentials.GetPasswordAsync();
        if (ftpPassword == null)
        {
            Console.WriteLine("No password entered, cannot connect to FTP server");
            return;
        }

        await using AsyncFtpClient client = new("52.51.224.238", "awsftp", ftpPassword);
        client.Config.ConnectTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;
        var connectionProfile = await client.AutoConnect();
        if (connectionProfile == null)
            return;

        Console.WriteLine("Connected successfully");

        var offlineFilename = $"{sitePath}/App_Offline.htm";
        if (setOffline)
        {
            if (await client.FileExists(offlineFilename))
            {
                Console.WriteLine("Site is already offline, nothing to do.");
            }
            else
            {
                await using MemoryStream emptyStream = new();
                await client.UploadStream(emptyStream, offlineFilename, existsMode: FtpRemoteExists.Skip, createRemoteDir: false);
                Console.WriteLine("Site is now OFFLINE");
            }
        }
        else
        {
            if (await client.FileExists(offlineFilename))
            {
                await client.DeleteFile(offlineFilename);
                Console.WriteLine("Site is now ONLINE");
            }
            else
            {
                Console.WriteLine("Site is already online, nothing to do.");
            }
        }
    }
}
