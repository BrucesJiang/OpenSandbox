// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Net;
using System.Text;
using FluentAssertions;
using OpenSandbox.Adapters;
using OpenSandbox.Internal;
using OpenSandbox.Models;
using Xunit;

namespace OpenSandbox.Tests;

public class FilesystemAdapterTests
{
    [Fact]
    public async Task WithIdentity_ShouldScopeJsonAndBinaryRequestsWithoutMutatingOriginal()
    {
        var handler = new IdentityCaptureHandler();
        using var client = new HttpClient(handler);
        const string baseUrl = "http://localhost:8080/sandboxes/example/port/44772";
        var headers = new Dictionary<string, string> { ["X-EXECD-ACCESS-TOKEN"] = "secret" };
        var wrapper = new HttpClientWrapper(client, baseUrl, headers);
        var original = new FilesystemAdapter(wrapper, baseUrl, headers);
        var scoped = original.WithIdentity(1001, 2000);

        await scoped.GetFileInfoAsync(new[] { "/file" });
        await scoped.ReadBytesAsync("/file");
        await scoped.WriteFilesAsync(new[] { new OpenSandbox.Models.WriteEntry { Path = "/file", Data = new byte[] { 0, 255, 1 } } });
        await original.GetFileInfoAsync(new[] { "/original" });

        handler.Paths.Should().Equal(
            "/sandboxes/example/port/44772/v1/filesystem/1001/2000/files/info",
            "/sandboxes/example/port/44772/v1/filesystem/1001/2000/files/download",
            "/sandboxes/example/port/44772/v1/filesystem/1001/2000/files/upload",
            "/sandboxes/example/port/44772/files/info");
        handler.Tokens.Should().OnlyContain(token => token == "secret");
        Action invalidUid = () => original.WithIdentity(uint.MaxValue, 0);
        invalidUid.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData("http://localhost:8080/v1/filesystem/")]
    [InlineData("http://localhost:8080/proxy/v1/filesystem/tenant/port/44772")]
    [InlineData("http://localhost:8080/proxy/V1/FILESYSTEM/tenant/port/44772/")]
    public async Task WithIdentity_ShouldPreserveProxyRootWhenRescoped(string baseUrl)
    {
        var handler = new IdentityCaptureHandler();
        using var client = new HttpClient(handler);
        var wrapper = new HttpClientWrapper(client, baseUrl);
        var original = new FilesystemAdapter(wrapper, baseUrl, new Dictionary<string, string>());
        OpenSandbox.Services.IIdentitySandboxFiles capability = original;
        var first = capability.WithIdentity(1, 2);
        var second = ((OpenSandbox.Services.IIdentitySandboxFiles)first).WithIdentity(3, 4);

        await first.GetFileInfoAsync(new[] { "/first" });
        await second.GetFileInfoAsync(new[] { "/second" });
        await original.GetFileInfoAsync(new[] { "/original" });

        var root = new Uri(baseUrl.TrimEnd('/')).AbsolutePath.TrimEnd('/');
        handler.Paths.Should().Equal(
            root + "/v1/filesystem/1/2/files/info",
            root + "/v1/filesystem/3/4/files/info",
            root + "/files/info");
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.NotImplemented)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task WithIdentity_ShouldNeverFallBack(HttpStatusCode status)
    {
        var handler = new IdentityCaptureHandler(status);
        using var client = new HttpClient(handler);
        var wrapper = new HttpClientWrapper(client, "http://localhost:8080");
        var original = new FilesystemAdapter(wrapper, wrapper.BaseUrl, new Dictionary<string, string>());
        var scoped = original.WithIdentity(1001, 2000);

        Func<Task> operation = () => scoped.DeleteFilesAsync(new[] { "/file" });
        await operation.Should().ThrowAsync<OpenSandbox.Core.SandboxApiException>();
        handler.Paths.Should().Equal("/v1/filesystem/1001/2000/files");
    }

    private sealed class IdentityCaptureHandler(HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public List<string> Paths { get; } = new();
        public List<string> Tokens { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            Tokens.Add(request.Headers.TryGetValues("X-EXECD-ACCESS-TOKEN", out var values) ? values.Single() : "");
            if (request.Content != null)
                await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(status == HttpStatusCode.OK ? "{}" : "{\"code\":\"FILESYSTEM_IDENTITY_UNAVAILABLE\",\"message\":\"unsupported\"}", Encoding.UTF8, "application/json")
            };
        }
    }

    [Fact]
    public async Task ListDirectoryAsync_ShouldParseEntryTypeAndSendDepthZero()
    {
        var payload = """
        [
          {
            "path": "/workspace/link",
            "type": "symlink",
            "size": 11,
            "modified_at": "2026-06-08T10:00:00Z",
            "created_at": "2026-06-08T10:00:00Z",
            "owner": "root",
            "group": "root",
            "mode": 777
          }
        ]
        """;
        var handler = new CaptureJsonHandler(payload);
        using var client = new HttpClient(handler);
        var wrapper = new HttpClientWrapper(client, "http://localhost:8080");
        var adapter = new FilesystemAdapter(wrapper, "http://localhost:8080", new Dictionary<string, string>());

        var entries = await adapter.ListDirectoryAsync("/workspace", depth: 0);

        handler.LastRequestUri.Should().NotBeNull();
        handler.LastRequestUri!.PathAndQuery.Should().Contain("/directories/list");
        handler.LastRequestUri!.Query.Should().Contain("path=%2Fworkspace");
        handler.LastRequestUri!.Query.Should().Contain("depth=0");
        entries.Should().ContainSingle();
        entries[0].Type.Should().Be("symlink");
    }

    [Fact]
    public async Task ListDirectoryAsync_ShouldOmitDepthWhenNull()
    {
        var handler = new CaptureJsonHandler("[]");
        using var client = new HttpClient(handler);
        var wrapper = new HttpClientWrapper(client, "http://localhost:8080");
        var adapter = new FilesystemAdapter(wrapper, "http://localhost:8080", new Dictionary<string, string>());

        var entries = await adapter.ListDirectoryAsync("/workspace");

        handler.LastRequestUri.Should().NotBeNull();
        handler.LastRequestUri!.Query.Should().Contain("path=%2Fworkspace");
        handler.LastRequestUri!.Query.Should().NotContain("depth=");
        entries.Should().BeEmpty();
    }

    [Fact]
    public async Task ReadBytesDetailedAsync_ShouldExposePartialMetadata()
    {
        var handler = new DownloadHandler();
        handler.Enqueue(DownloadResponse(
            HttpStatusCode.PartialContent,
            "hello",
            contentRange: "bytes 0-4/10",
            contentType: "application/octet-stream",
            contentDisposition: "attachment; filename=\"data.bin\""));
        using var client = new HttpClient(handler);
        var adapter = CreateAdapter(client);

        var response = await adapter.ReadBytesDetailedAsync(
            "/data.bin",
            new ReadBytesOptions { Range = "bytes=0-4" });

        response.Body.Should().Equal(Encoding.UTF8.GetBytes("hello"));
        response.StatusCode.Should().Be(206);
        response.IsPartial.Should().BeTrue();
        response.ContentType.Should().Be("application/octet-stream");
        response.ContentDisposition.Should().Be("attachment; filename=\"data.bin\"");
        response.ContentLength.Should().Be(5);
        response.TotalSize.Should().Be(10);
        response.ContentRange.Should().Be(new ByteRange(0, 4, 10, "bytes 0-4/10"));
        handler.LastRange.Should().Be("bytes=0-4");
    }

    [Fact]
    public async Task ReadBytesDetailedAsync_ShouldIdentifyIgnoredRange()
    {
        var handler = new DownloadHandler();
        handler.Enqueue(DownloadResponse(HttpStatusCode.OK, "whole file"));
        using var client = new HttpClient(handler);
        var adapter = CreateAdapter(client);

        var response = await adapter.ReadBytesDetailedAsync(
            "/data.bin",
            new ReadBytesOptions { Range = "bytes=5-" });

        response.IsPartial.Should().BeFalse();
        response.ContentRange.Should().BeNull();
        response.ContentLength.Should().Be(10);
        response.TotalSize.Should().Be(10);
    }

    [Fact]
    public async Task ReadBytesDetailedAsync_ShouldPreserveInvalidAndUnknownRanges()
    {
        var handler = new DownloadHandler();
        handler.Enqueue(DownloadResponse(HttpStatusCode.PartialContent, "hello", "garbage"));
        handler.Enqueue(DownloadResponse(HttpStatusCode.PartialContent, "hello", "bytes 5-9/*"));
        using var client = new HttpClient(handler);
        var adapter = CreateAdapter(client);

        var invalid = await adapter.ReadBytesDetailedAsync("/data.bin");
        var unknown = await adapter.ReadBytesDetailedAsync("/data.bin");

        invalid.ContentRange.Should().Be(new ByteRange(-1, -1, -1, "garbage"));
        invalid.TotalSize.Should().Be(-1);
        unknown.ContentRange.Should().Be(new ByteRange(5, 9, -1, "bytes 5-9/*"));
        unknown.TotalSize.Should().Be(-1);
    }

    [Fact]
    public async Task DetailedAndLegacyReads_ShouldReturnResponseBodies()
    {
        var handler = new DownloadHandler();
        handler.Enqueue(DownloadResponse(HttpStatusCode.PartialContent, "hello", "bytes 0-4/10"));
        handler.Enqueue(DownloadResponse(HttpStatusCode.OK, "hello"));
        handler.Enqueue(DownloadResponse(HttpStatusCode.OK, "hello"));
        using var client = new HttpClient(handler);
        var adapter = CreateAdapter(client);

        var detailed = await adapter.ReadBytesStreamDetailedAsync("/data.bin");
        detailed.IsPartial.Should().BeTrue();
        (await CollectAsync(detailed.Body)).Should().Equal(Encoding.UTF8.GetBytes("hello"));
        (await adapter.ReadBytesAsync("/data.bin")).Should().Equal(Encoding.UTF8.GetBytes("hello"));
        (await CollectAsync(adapter.ReadBytesStreamAsync("/data.bin"))).Should().Equal(Encoding.UTF8.GetBytes("hello"));
    }

    [Fact]
    public async Task DetailedStreams_ShouldDisposeUnconsumedAndPartialBodies()
    {
        var unconsumedContent = new TrackingContent("hello");
        var partialContent = new TrackingContent("hello");
        var handler = new DownloadHandler();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = unconsumedContent });
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = partialContent });
        using var client = new HttpClient(handler);
        var adapter = CreateAdapter(client);

        var unconsumed = await adapter.ReadBytesStreamDetailedAsync("/data.bin");
        await unconsumed.Body.DisposeAsync();
        unconsumedContent.Disposed.Should().BeTrue();

        var partial = await adapter.ReadBytesStreamDetailedAsync("/data.bin");
        await foreach (var _ in partial.Body)
        {
            break;
        }
        partialContent.Disposed.Should().BeTrue();
    }

    private static FilesystemAdapter CreateAdapter(HttpClient client)
    {
        var wrapper = new HttpClientWrapper(client, "http://localhost:8080");
        return new FilesystemAdapter(wrapper, client, "http://localhost:8080", new Dictionary<string, string>());
    }

    private static HttpResponseMessage DownloadResponse(
        HttpStatusCode statusCode,
        string body,
        string? contentRange = null,
        string? contentType = null,
        string? contentDisposition = null)
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        if (contentRange != null)
        {
            content.Headers.TryAddWithoutValidation("Content-Range", contentRange);
        }
        if (contentType != null)
        {
            content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }
        if (contentDisposition != null)
        {
            content.Headers.TryAddWithoutValidation("Content-Disposition", contentDisposition);
        }
        return new HttpResponseMessage(statusCode) { Content = content };
    }

    private static async Task<byte[]> CollectAsync(IAsyncEnumerable<byte[]> chunks)
    {
        using var stream = new MemoryStream();
        await foreach (var chunk in chunks)
        {
            await stream.WriteAsync(chunk);
        }
        return stream.ToArray();
    }

    private sealed class CaptureJsonHandler(string payload) : HttpMessageHandler
    {
        public Uri? LastRequestUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }

    private sealed class DownloadHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses = new();

        public string? LastRange { get; private set; }

        public void Enqueue(HttpResponseMessage response) => _responses.Enqueue(response);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRange = request.Headers.TryGetValues("Range", out var values)
                ? values.SingleOrDefault()
                : null;
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private sealed class TrackingContent(string body) : ByteArrayContent(Encoding.UTF8.GetBytes(body))
    {
        public bool Disposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
