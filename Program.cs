using System.Diagnostics;
using System.Text.Json;
using AwsEc2SecurityGroups;

while (await RunAppAsync());

static async Task<bool> RunAppAsync()
{
    Console.WriteLine(@"
AWS EC2 Security Groups
=======================

1. View current rules
2. Enable FTP ports
3. Enable RDP port
4. Reset to just HTTP/HTTPS rules
x. Exit
");
    Console.Write("Option: ");
    var opt = Console.ReadLine();
    switch (opt)
    {
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
            await ResetRulesAsync();
            break;
        case "x":
            return false;
    }

    return true;
}

static async Task EnablePortAsync(int fromPort, int? toPort = null)
{
    var externalIp = (await new HttpClient().GetStringAsync("https://checkip.amazonaws.com")).Trim();
    Console.WriteLine($"My ip {externalIp}");
    var response = await CallAwsCliAsync<SecurityGroupRulesResponse>($"ec2 authorize-security-group-ingress --group-id sg-05253497db119d9e0 --protocol tcp --port {(toPort == null ? fromPort : $"\"{fromPort}-{toPort}\"")} --cidr {externalIp}/32");
    Console.WriteLine(response.Return ?? false ? $"Successfully added rule for port {(toPort == null ? fromPort : $"{fromPort}-{toPort}")}" : "Failed adding rule");
    Console.WriteLine("New rule:");
    foreach (var rule in (response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>()).Where(x => !x.IsEgress))
        Console.WriteLine($"{rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
}

static async Task ViewRulesAsync()
{
    var response = await CallAwsCliAsync<SecurityGroupRulesResponse>("ec2 describe-security-group-rules --filter \"Name=group-id,Values=sg-05253497db119d9e0\"");
    Console.WriteLine("Rules:");
    Console.WriteLine("----");
    foreach (var rule in (response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>()).Where(x => !x.IsEgress))
        Console.WriteLine($"{rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
    Console.WriteLine("----");
}

static async Task ResetRulesAsync()
{
    var response = await CallAwsCliAsync<SecurityGroupRulesResponse>("ec2 describe-security-group-rules --filter \"Name=group-id,Values=sg-05253497db119d9e0\"");
    var removedCount = 0;
    foreach (var rule in response.SecurityGroupRules ?? Enumerable.Empty<SecurityGroupRule>())
    {
        if (rule.IsEgress || rule.FromPort == 80 || rule.FromPort == 443)
            continue;
        
        Console.WriteLine($"Removing rule {rule.SecurityGroupRuleId}: [{rule.IpProtocol}] {rule.FromPort}{(rule.ToPort == rule.FromPort ? "" : $"-{rule.ToPort}")} {rule.CidrIpv4}");
        var removeResponse = await CallAwsCliAsync<SecurityGroupRulesResponse>($"ec2 revoke-security-group-ingress --group-id sg-05253497db119d9e0 --security-group-rule-ids {rule.SecurityGroupRuleId}");
        Console.WriteLine(removeResponse.Return ?? false ? $"Successfully remove rule {rule.SecurityGroupRuleId}" : "Failed removing rule");

        removedCount++;
    }

    if (removedCount == 0)
        Console.WriteLine("No custom rules, nothing removed.");
}

static async Task<T> CallAwsCliAsync<T>(string args)
{
    ProcessStartInfo procInfo = new("aws")
    {
        Arguments = args,
        RedirectStandardOutput = true
    };
    var proc = Process.Start(procInfo) ?? throw new InvalidOperationException("Could not run aws cli");
    await proc.WaitForExitAsync();
    var jsonOutput = await proc.StandardOutput.ReadToEndAsync();
    return JsonSerializer.Deserialize<T>(jsonOutput) ?? throw new InvalidOperationException("Invalid aws cli response: " + jsonOutput);
}
