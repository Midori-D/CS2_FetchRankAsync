namespace FiveERankCrawlerLib;

using HtmlAgilityPack;
using Microsoft.Playwright;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;

public sealed record FetchOptions
{
    public bool Debug { get; init; } = false;
    public bool DebugDumps { get; init; } = false;
    public bool ForceHttps { get; init; } = true;
    public bool StripUrlQuery { get; init; } = true;
    public bool StripUrlFragment { get; init; } = true;
    public bool UseChrome { get; init; } = false;

    public int CacheMaxEntries { get; init; } = 1024;

    public int HttpTimeoutSeconds { get; init; } = 8;
    public int HtmlMaxBytes { get; init; } = 2_000_000;
    public int HttpMaxRetries { get; init; } = 3;

    public int ThrottleConcurrency { get; init; } = 2;
    public int ThrottleDelayMinMs { get; init; } = 150;
    public int ThrottleDelayMaxMs { get; init; } = 400;

    public int MemoryCacheTtlSeconds { get; init; } = 120;

    public int PlaywrightGotoTimeoutMs { get; init; } = 45_000;
    public int PlaywrightIdleTimeoutMs { get; init; } = 20_000;
    public int PlaywrightOverallTimeoutMs { get; init; } = 60_000;

    public string AllowedRoot { get; init; } = "5eplay.com";
    public string UserAgent { get; init; } =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    public string AcceptLanguage { get; init; } = "en-US,en;q=0.9";
    public string Locale { get; init; } = "en-US";
    public string TimezoneId { get; init; } = "UTC";
}

public sealed class RankInfo
{
    public string? Rank { get; init; } // Rank, ex) "A"
    public string? FileName { get; init; } // Rank FileName, ex) "A_d.png"
    public string? Src { get; init; } // URL
    public bool IsAnimated => Src?.EndsWith(".gif", StringComparison.OrdinalIgnoreCase) == true;
}

public static class RankFetcher
{
    public static FetchOptions Options { get; private set; } = new();
    public static void Configure(FetchOptions options)
    {
        Options = options ?? new();
        _http?.Dispose();
        _http = BuildHttpClient();
        var n = Math.Max(1, Options.ThrottleConcurrency);
        _hostGate?.Dispose();
        _hostGate = new SemaphoreSlim(n, n);
    }

    // A. Constants, Fields, Regular Expressions
    private const string PageBase = "https://arena.5eplay.com";
    private static readonly Regex LevelImgRegex = new(
        @"https?:\/\/[^\s""']*\/level_2025\/[A-Za-z0-9_]+(?:\.png|\.gif)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(500));
    private static readonly SocketsHttpHandler _handler = new() // HttpClient 
    {
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectTimeout = TimeSpan.FromSeconds(5)
    };
    private static HttpClient _http = BuildHttpClient();
    private static SemaphoreSlim _hostGate = new(initialCount: 2, maxCount: 2); // Concurrency Limit
    private static readonly ConcurrentDictionary<string, (RankInfo Info, DateTime TsUtc)> _cache = new(); // Memory Cache (Prevent Same Player Viewing)
    private static readonly ConcurrentQueue<string> _cacheOrder = new();

    // B. Public API
    public static async Task<RankInfo> FetchRankAsync(string playerId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(playerId, out var hit)) // Memory Cache Hit Check
        {
            var ttl = TimeSpan.FromSeconds(Math.Max(Options.MemoryCacheTtlSeconds, 10));
            if (DateTime.UtcNow - hit.TsUtc < ttl)
            return hit.Info;
        }

        var viaHttp = await TryFetchViaHttpAsync(playerId, ct); // HTTP Crawling
        if (viaHttp is not null && viaHttp.Rank is not null)
        {
            CacheSet(playerId, viaHttp);
            return viaHttp;
        }

        if (viaHttp is null)
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] INFO  🚧 WAF 감지 → Playwright 폴백 (playerId={playerId})");
        else
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] INFO  🔁 HTML 분석 실패 → Playwright 폴백 (playerId={playerId}))");

        try // Playwright Fallback
        {
            var viaPw = await FetchViaPlaywrightAsync(playerId, ct);
            CacheSet(playerId, viaPw);
            return viaPw;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] ERROR  🚨 Playwright 폴백 실패: {ex.Message}");
            throw;
        }
    }

    // C. Core
    private static async Task<RankInfo?> TryFetchViaHttpAsync(string playerId, CancellationToken ct)
    {
        var url = BuildPlayerUrl(playerId);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        ApplyHttpHeaders(req);

        using var res = await SendWithRetryAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var content = res.Content;

        var cap = Options.HtmlMaxBytes > 0 ? Options.HtmlMaxBytes : 2_000_000; // HTML Max Bytes (2MB)

        if (content.Headers.ContentLength is long len && len > cap)  // Block If Content-Length Is Present
            throw new InvalidDataException($"payload too large: {len} bytes");

        try // Prevent Buffering
        {
            await content.LoadIntoBufferAsync(cap);
        }
        catch (HttpRequestException)
        {
            throw new InvalidDataException("payload too large (buffer cap)");
        }

        var mt = content.Headers.ContentType?.MediaType;  // MIME Guard (html/xml...)
        if (mt is not null && !(mt.Contains("html", StringComparison.OrdinalIgnoreCase) ||
            mt.Contains("xml", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException($"unexpected content-type: {mt}");

        var html = await content.ReadAsStringAsync(ct);

        if (html.Contains("acw_sc__v2", StringComparison.OrdinalIgnoreCase) || // JS Challenge/WAF
            (html.Contains("document.cookie", StringComparison.OrdinalIgnoreCase) &&
             html.Contains("location.reload", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var doc = new HtmlDocument(); // DOM(Document Object Model) Parsing
        doc.LoadHtml(html);

        var node =
            doc.DocumentNode.SelectSingleNode("//img[@class='lego_level2025_img']") ??
            doc.DocumentNode.SelectSingleNode("//img[contains(@class,'lego_level2025_img')]") ??
            doc.DocumentNode.SelectSingleNode("//img[contains(@src,'/level_2025/')]");

        string src = "";
        if (node is not null)
        {
            src = node.GetAttributeValue("src", string.Empty);
            if (string.IsNullOrWhiteSpace(src)) src = node.GetAttributeValue("data-src", string.Empty);
            if (string.IsNullOrWhiteSpace(src)) src = node.GetAttributeValue("data-original", string.Empty);

            if (string.IsNullOrWhiteSpace(src))
            {
                var srcset = node.GetAttributeValue("srcset", string.Empty);
                if (!string.IsNullOrWhiteSpace(srcset))
                {
                    var first = srcset.Split(',')[0].Trim();
                    var spaceIdx = first.IndexOf(' ');
                    src = spaceIdx > 0 ? first[..spaceIdx] : first;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(src)) // Last Resort : HTML Regular Expression Scan
        {
            var m = LevelImgRegex.Match(html);
            if (m.Success) src = m.Value;
        }

        src = NormalizeUrlStrict(src);
        if (string.IsNullOrWhiteSpace(src))
            return new RankInfo();

        var fileName = SafeFileNameFromUrl(src);
        var rank = ExtractRankFromFileName(fileName);

        return new RankInfo { Rank = rank, FileName = fileName, Src = src };
    }

    private static async Task<RankInfo> FetchViaPlaywrightAsync(string playerId, CancellationToken ct) // Playwright Fallback
    {
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(NewLaunchOptions());
        var context = await browser.NewContextAsync(NewContextOptions());
        IPage? page = null;
        var url = BuildPlayerUrl(playerId);

        using var overallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        overallCts.CancelAfter(TimeSpan.FromMilliseconds(
            Math.Max(5_000, Options.PlaywrightOverallTimeoutMs)));
        try
        {
            page = await context.NewPageAsync();

            await page.GotoAsync(url, new()
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = Math.Max(5_000, Options.PlaywrightGotoTimeoutMs)
            });
            try
            {
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle,
                new() { Timeout = Math.Max(3_000, Options.PlaywrightIdleTimeoutMs) });
            }
            catch { /* noop */ }
            if (!Options.Debug) await page.WaitForTimeoutAsync(800);

            string? src = null;
            const string selector = "img.lego_level2025_img, img[src*='/level_2025/']";

            try
            {
                var loc = page.Locator(selector).First;
                await loc.WaitForAsync(new() { State = WaitForSelectorState.Attached, Timeout = 15000 });
                var el = await loc.ElementHandleAsync();
                if (el is not null)
                {
                    src = await el.GetAttributeAsync("src")
                       ?? await el.GetAttributeAsync("data-src")
                       ?? await el.GetAttributeAsync("data-original");
                }
            }
            catch { /* ignore and continue */ }

            if (string.IsNullOrWhiteSpace(src)) // Full Frame Scan
            {
                foreach (var f in page.Frames)
                {
                    var el = await f.QuerySelectorAsync(selector);
                    if (el is not null)
                    {
                        src = await el.GetAttributeAsync("src")
                           ?? await el.GetAttributeAsync("data-src")
                           ?? await el.GetAttributeAsync("data-original");
                        if (!string.IsNullOrWhiteSpace(src)) break;
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(src)) // JS Scan(document.images)
            {
                src = await page.EvaluateAsync<string?>(@"() => {
                    const imgs = Array.from(document.images);
                    const hit = imgs.find(i => i.src.includes('/level_2025/'));
                    return hit ? hit.src : null;
                }");
            }

            if (string.IsNullOrWhiteSpace(src)) // Last Resort : HTML Regular Expression Scan
            {
                overallCts.Token.ThrowIfCancellationRequested();
                var html = await page.ContentAsync();
                var m = LevelImgRegex.Match(html);
                if (m.Success) src = m.Value;
            }

            src = NormalizeUrlStrict(src ?? "");
            if (string.IsNullOrWhiteSpace(src))
                return new RankInfo();

            var fileName = SafeFileNameFromUrl(src);
            var rank = ExtractRankFromFileName(fileName);
            return new RankInfo { Rank = rank, FileName = fileName, Src = src };
        }
        finally
        {
#if DEBUG
            if (Options.Debug && Options.DebugDumps && page is not null)
            {
                string? htmlPath = null;
                try
                {
                    var html = await page.ContentAsync();

                    if (html.Length <= Options.HtmlMaxBytes)
                    {
                        htmlPath = MakeDumpPath(playerId, "html");
                        await File.WriteAllTextAsync(htmlPath, html, ct);
                    }

                    var pngPath = MakeDumpPath(playerId, "png");
                    await page.ScreenshotAsync(new() { Path = pngPath, FullPage = true });

                    Console.WriteLine($"[dbg] dumps -> {(htmlPath is null ? "(html skipped)" : htmlPath)} | {pngPath}");
                }
                catch (OperationCanceledException) { /* ignore */ }
                catch (Exception ex) { Console.WriteLine($"[dbg] dump failed: {ex.Message}"); }
            }
#endif
            await context.CloseAsync();
        }
    }

    //D. Helpers
    private static async Task<HttpResponseMessage> SendWithRetryAsync(HttpRequestMessage req, CancellationToken ct)
    {
        var max = Options.HttpMaxRetries <= 0 ? 3 : Options.HttpMaxRetries;

        for (var attempt = 1; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            await _hostGate.WaitAsync(ct); // Concurrency Limit
            try
            {
                await Task.Delay(JitterDelay(), ct); // Await Task

                var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

                // 429/5xx Retry
                if ((int)res.StatusCode == 429 || (int)res.StatusCode >= 500)
                {
                    var retryAfter = res.Headers.RetryAfter?.Delta ?? TimeSpan.Zero;
                    if (attempt <= max)
                    {
                        res.Dispose();
                        await Task.Delay(retryAfter != TimeSpan.Zero ? retryAfter : Backoff(attempt), ct);
                        continue;
                    }
                }

                return res;
            }
            catch (TaskCanceledException) when (attempt <= max)
            {
                await Task.Delay(Backoff(attempt), ct);
            }
            finally
            {
                _hostGate.Release();
            }
        }
    }

    private static BrowserNewContextOptions NewContextOptions() => new() // Playwright ContextOptions
    {
        UserAgent = Options.UserAgent,
        Locale = Options.Locale,
        TimezoneId = Options.TimezoneId,
        AcceptDownloads = false,
        ViewportSize = new() { Width = 1280, Height = 800 },
    };
    private static BrowserTypeLaunchOptions NewLaunchOptions() => new() // Playwright LaunchOptions
    {
        Headless = !Options.Debug,
        SlowMo = Options.Debug ? 120 : 0,
        Channel = Options.UseChrome ? "chrome" : null,
        Args = new[] { "--disable-blink-features=AutomationControlled" }
    };

    private static HttpClient BuildHttpClient()
    {
        var c = new HttpClient(_handler, disposeHandler: false);
        var seconds = Options.HttpTimeoutSeconds > 0 ? Options.HttpTimeoutSeconds : 8;
        c.Timeout = TimeSpan.FromSeconds(seconds);
        return c;
    }

    private static TimeSpan JitterDelay()
    {
        var min = Math.Max(0, Options.ThrottleDelayMinMs);
        var max = Math.Max(min, Options.ThrottleDelayMaxMs);
        return TimeSpan.FromMilliseconds(Random.Shared.Next(min, max + 1));
    }
    static TimeSpan Backoff(int attempt)
    {
        var baseMs = (int)Math.Pow(2, attempt) * 100;
        var jitter = Random.Shared.Next(80, 220);
        return TimeSpan.FromMilliseconds(baseMs + jitter);
    }

    private static string BuildPlayerUrl(string playerId)
    {
        var safeId = Uri.EscapeDataString(playerId);
        return $"https://arena.5eplay.com/data/player/{safeId}";
    }

    private static string NormalizeUrlStrict(string? url) // *.5eplay.com Only Allowance
    {
        if (string.IsNullOrWhiteSpace(url)) return "";

        var s = url.Trim();
        if (s.StartsWith("//")) s = "https:" + s;
        else if (s.StartsWith("/")) s = PageBase + s;
        else if (!s.StartsWith("http", StringComparison.OrdinalIgnoreCase)) s = "https:" + s;

        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri)) return "";

        if (uri.Scheme is not ("http" or "https")) return "";  // Https Forcing
        if (Options.ForceHttps && uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            var up = new UriBuilder(uri) { Scheme = Uri.UriSchemeHttps, Port = -1 };
            uri = up.Uri;
        }

        var host = uri.IdnHost.TrimEnd('.'); // WhiteList
        var root = Options.AllowedRoot.Trim().TrimStart('.');
        var allowed = host.Equals(root, StringComparison.OrdinalIgnoreCase)
                   || host.EndsWith("." + root, StringComparison.OrdinalIgnoreCase);
        if (!allowed) return "";

        if (Options.StripUrlQuery || Options.StripUrlFragment) // Remove ?query/#fragment
        {
            var ub = new UriBuilder(uri);
            if (Options.StripUrlQuery) ub.Query = string.Empty;
            if (Options.StripUrlFragment) ub.Fragment = string.Empty;
            uri = ub.Uri;
        }

        return uri.ToString();
    }

    private static string SafeFileNameFromUrl(string url)
    {
        try { return Path.GetFileName(new Uri(url).LocalPath); }
        catch
        {
            var ix = url.LastIndexOf('/');
            return ix >= 0 ? url[(ix + 1)..] : url;
        }
    }

    private static readonly string DumpRoot =
    Path.Combine(Path.GetTempPath(), "5ERankCrawler", "dumps");

    private static readonly string RunId =
        DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4));

    // EphemeralSalt
    private static readonly string EphemeralSalt =
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static string MakeDumpPath(string playerId, string ext)
    {
        var salt = EphemeralSalt;
        using var sha = SHA256.Create();
        var tag = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes($"{salt}:{playerId}")))[..8];

        var dir = Path.Combine(DumpRoot, RunId);
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"pw_{tag}.{ext}");
    }

    // "A_d.png" -> "A", "A2_d.png" -> "A+", "ques_d.png" -> "Unrank"
    private static string? ExtractRankFromFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return null;

        var stem = Path.GetFileNameWithoutExtension(fileName);
        if (string.IsNullOrEmpty(stem)) return null;

        // ques_d.png
        if (stem.StartsWith("ques", StringComparison.OrdinalIgnoreCase))
            return "Unrank";

        // Delimiter 
        var m = Regex.Match(stem, @"^([A-Da-d])(2)?(?:[_-]|$)",
            RegexOptions.None, TimeSpan.FromMilliseconds(200));
        if (!m.Success) return null;

        var letter = m.Groups[1].Value.ToUpperInvariant();
        var plus = m.Groups[2].Success;

        return plus ? $"{letter}+" : letter;
    }

    private static void ApplyHttpHeaders(HttpRequestMessage req)
    {
        req.Headers.UserAgent.ParseAdd(Options.UserAgent);
        req.Headers.Accept.Clear();
        req.Headers.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        req.Headers.AcceptLanguage.Clear();
        req.Headers.AcceptLanguage.ParseAdd(Options.AcceptLanguage);
    }

    private static void CacheSet(string key, RankInfo info)
    {
        _cache[key] = (info, DateTime.UtcNow);
        _cacheOrder.Enqueue(key);

        var limit = Math.Max(128, Options.CacheMaxEntries);
        while (_cache.Count > limit && _cacheOrder.TryDequeue(out var old))
        {
            _cache.TryRemove(old, out _);
        }
    }
}
