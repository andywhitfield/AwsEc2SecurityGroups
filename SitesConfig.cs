namespace AwsEc2SecurityGroups;

public class SitesConfig
{
    public required IEnumerable<SiteConfig> SiteConfig { get; set; }
}

public class SiteConfig
{
    public required string Name { get; set; }
    public required string Path { get; set; }
}