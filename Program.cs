using AwsEc2SecurityGroups;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

try
{
    var builder = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddEnvironmentVariables();
    var configuration = builder.Build();

    var host = Host
        .CreateDefaultBuilder(args)
        .ConfigureServices(services =>
        {
            var dir = new DirectoryInfo(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AwsEc2SecurityGroups-Keys"));
            Console.WriteLine("Persisting keys to: " + dir.FullName);
            services.AddDataProtection().PersistKeysToFileSystem(dir);
            services
                .AddSingleton<IConfiguration>(configuration)
                .Configure<SitesConfig>(configuration.GetSection("Sites"))
                .AddScoped<FtpCredentials>()
                .AddScoped<AwsCommand>()
                .AddScoped<FtpCommand>()
                .AddScoped<CliService>();
        })
        .Build();

    await using var serviceScope = host.Services.CreateAsyncScope();
    while (await serviceScope.ServiceProvider.GetRequiredService<CliService>().RunAppAsync()) { }
}
catch (Exception ex)
{
    Console.WriteLine($"Application error, exiting! {ex}");
    Environment.Exit(1);
}
