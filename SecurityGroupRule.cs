namespace AwsEc2SecurityGroups;

public class SecurityGroupRule
{
    public string? SecurityGroupRuleId { get; set; }
    public string? GroupId { get; set; }
    public string? GroupOwnerId { get; set; }
    public bool IsEgress { get; set; }
    public string? IpProtocol { get; set; }
    public int FromPort { get; set; }
    public int ToPort { get; set; }
    public string? CidrIpv4 { get; set; }
    public string[]? Tags { get; set; }
    public string? SecurityGroupRuleArn { get; set; }
}
