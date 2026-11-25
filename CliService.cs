using Microsoft.Extensions.Options;

namespace AwsEc2SecurityGroups;

public class CliService(IOptionsSnapshot<SitesConfig> config, AwsCommand awsCommand, FtpCommand ftpCommand)
{
    public async Task<bool> RunAppAsync()
    {
        Console.WriteLine(@"
AWS EC2 Security Groups
=======================

0. Reset to just HTTP/HTTPS rules
1. View current rules
2. Enable FTP ports
3. Enable RDP port
4. Toggle site offline / online
x. Exit
");
        Console.Write("Option: ");
        var opt = Console.ReadLine();
        switch (opt)
        {
            case "0":
                await ResetRulesAsync();
                break;
            case "1":
                await ViewRulesAsync();
                break;
            case "2":
                await EnablePortAsync(21);
                await EnablePortAsync(1024, 1030);
                break;
            case "3":
                await EnablePortAsync(3389);
                break;
            case "4":
                await ToggleSiteOfflineAsync();
                break;
            case "x":
                return false;
        }

        return true;
    }

    private async Task EnablePortAsync(int fromPort, int? toPort = null)
    {
        var externalIp = (await new HttpClient().GetStringAsync("https://checkip.amazonaws.com")).Trim();
        Console.WriteLine($"My ip {externalIp}");
        var response = await awsCommand.CallAwsCliAsync<SecurityGroupRulesResponse>($"ec2 authorize-security-group-ingress --group-id sg-05253497db119d9e0 --protocol tcp --port {(toPort == null ? fromPort : $"\"{fromPort}-{toPort}\"")} --cidr {externalIp}/32");
        Console.WriteLine(response.Return ?? false ? $"Successfully added rule for port {(toPort == null ? fromPort : $"{fromPort}-{toPort}")}" : "Failed adding rule");
        Console.WriteLine("New rule:");
        foreach (var rule in (response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>()).Where(x => !x.IsEgress))
            Console.WriteLine($"{rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
    }

    private async Task ViewRulesAsync()
    {
        var response = await awsCommand.CallAwsCliAsync<SecurityGroupRulesResponse>("ec2 describe-security-group-rules --filter \"Name=group-id,Values=sg-05253497db119d9e0\"");
        Console.WriteLine("Rules:");
        Console.WriteLine("----");
        foreach (var rule in (response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>()).Where(x => !x.IsEgress))
            Console.WriteLine($"{rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
        Console.WriteLine("----");
    }

    private async Task ResetRulesAsync()
    {
        var response = await awsCommand.CallAwsCliAsync<SecurityGroupRulesResponse>("ec2 describe-security-group-rules --filter \"Name=group-id,Values=sg-05253497db119d9e0\"");
        var removedCount = 0;
        foreach (var rule in response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>())
        {
            if (rule.IsEgress || rule.FromPort == 80 || rule.FromPort == 443)
                continue;

            Console.WriteLine($"Removing rule {rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
            var removeResponse = await awsCommand.CallAwsCliAsync<SecurityGroupRulesResponse>($"ec2 revoke-security-group-ingress --group-id sg-05253497db119d9e0 --security-group-rule-ids {rule.SecurityGroupRuleId}");
            Console.WriteLine(removeResponse.Return ?? false ? $"Successfully remove rule {rule.SecurityGroupRuleId}" : "Failed removing rule");

            removedCount++;
        }

        if (removedCount == 0)
            Console.WriteLine("No custom rules, nothing removed.");
    }

    private async Task ToggleSiteOfflineAsync()
    {
        var sites = config.Value.SiteConfig.ToArray();

        Console.WriteLine(@"
Choose site:
0. Reset FTP password");
        for (int i = 0; i < sites.Length; i++)
            Console.WriteLine("{0}. {1}", i + 1, sites[i].Name);

        Console.Write("Site: ");
        var opt = Console.ReadLine();

        if (opt == "0")
        {
            ftpCommand.ClearFtpCredentials();
            return;
        }

        if (!int.TryParse(opt, out var siteNum) || siteNum < 1 || siteNum > sites.Length)
        {
            Console.WriteLine("Invalid option");
            return;
        }

        var site = sites[siteNum - 1];
        Console.WriteLine(@"
Take offline or online:
1. Offline
2. Online
");
        Console.Write("Offline or online [2]: ");
        opt = Console.ReadLine();
        var offline = opt switch
        {
            "1" => true,
            _ => false,
        };
        Console.Write("Taking site {0} {1}. Continue? [Y] ", site.Name, offline ? "offline" : "online");
        opt = Console.ReadLine();
        if (!string.IsNullOrEmpty(opt) && !string.Equals(opt, "Y", StringComparison.OrdinalIgnoreCase))
            return;

        await ftpCommand.ToggleOfflineAsync(site.Path, offline);
    }
}