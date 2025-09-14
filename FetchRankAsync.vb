Imports System.Diagnostics
Imports System.Text.Json
Imports Microsoft.Extensions.Configuration
Imports FiveERankCrawlerLib

Module Program
    Sub Main(args As String())
        Dim env = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
        If String.IsNullOrWhiteSpace(env) Then env = "Production"

        Console.OutputEncoding = System.Text.Encoding.UTF8
        If args Is Nothing OrElse args.Length = 0 Then
            Console.WriteLine("사용법: dotnet run -- <5E_player_id>")
            Return
        End If

        ' Load appsettings.json
        Dim config = (New ConfigurationBuilder()) _
            .SetBasePath(AppContext.BaseDirectory) _
            .AddJsonFile("appsettings.json", optional:=True, reloadOnChange:=False) _
            .AddJsonFile($"appsettings.{env}.json", optional:=True) _
            .Build()

        ' Options
        Dim opts = config.GetSection("Crawler").Get(Of FetchOptions)()
        If opts Is Nothing Then
            opts = New FetchOptions With {
        .Debug = config.GetValue(Of Boolean)("Debug", False),
        .UseChrome = config.GetValue(Of Boolean)("UseChrome", False)
               }
        End If

        RankFetcher.Configure(opts)

        Dim playerId = args(0)
        Dim sw = Stopwatch.StartNew()
        Dim info = RankFetcher.FetchRankAsync(playerId).GetAwaiter().GetResult()
        sw.Stop()

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] INFO  ✅ VB FetchRank 완료 | id={playerId} | {sw.ElapsedMilliseconds}ms")
        Console.WriteLine("[DATA] " & JsonSerializer.Serialize(info, New JsonSerializerOptions With {.WriteIndented = True}))
    End Sub
End Module
