using System.Diagnostics;
using System.Text.Json;

namespace AwsEc2SecurityGroups;

public class AwsCommand
{
    public async Task<T> CallAwsCliAsync<T>(string args)
    {
        var callerIdentityOutput = await InvokeCommandAsync("sts get-caller-identity");
        bool isLoggedIn;
        try
        {
            var callerIdentity = JsonSerializer.Deserialize<AwsCallerIdentity>(callerIdentityOutput);
            isLoggedIn = callerIdentity?.UserId != null;
        }
        catch
        {
            isLoggedIn = false;
        }

        if (!isLoggedIn)
        {
            Console.WriteLine("Not currently logged on, calling aws login...");
            await InvokeCommandAsync("login");
        }

        return await InvokeAwsCommandAsync<T>(args);
    }

    private static async Task<T> InvokeAwsCommandAsync<T>(string args)
    {
        var jsonOutput = await InvokeCommandAsync(args);
        return JsonSerializer.Deserialize<T>(jsonOutput) ?? throw new InvalidOperationException("Invalid aws cli response: " + jsonOutput);
    }

    private static async Task<string> InvokeCommandAsync(string args)
    {
        ProcessStartInfo procInfo = new("aws")
        {
            Arguments = args,
            RedirectStandardOutput = true
        };
        var proc = Process.Start(procInfo) ?? throw new InvalidOperationException("Could not run aws cli");
        await proc.WaitForExitAsync();
        return await proc.StandardOutput.ReadToEndAsync();
    }
}
