"""Outbound HTTP calls are hinted whatever receiver expression carries them.

A call whose name only an HTTP client has is a fetch on any receiver, and so
is a generic name chained straight off the client it is made from: `new
URL(u).openStream()`, `HttpClient.newHttpClient().send(...)`,
`GetClient().GetAsync(u)`. A generic name on a plain variable (`.send(`,
`.getInputStream(`, `.GetAsync(`, `.SendAsync(`) still needs that variable to
be an HTTP client. Go hints `Do` on any receiver named a client and on any
variable bound to a `net/http` client.
"""
from __future__ import annotations

from assess.lib.treesitter_index import index_file


def _fetch_lines(file_path: str, language: str, source: bytes) -> list[int]:
    indexed = index_file(file_path, language, source)
    assert indexed["analysis_status"] == "complete"
    return sorted(sink["line"] for sink in indexed["security_sinks"] if sink["kind"] == "url_fetch")


def test_java_fetch_chained_off_its_client_is_hinted_and_a_plain_generic_call_is_gated() -> None:
    source = b"""import java.net.URL;
import java.net.http.HttpClient;
class Fetcher {
    byte[] open(String target) throws Exception {
        return new URL(target).openStream().readAllBytes();
    }
    String send(HttpRequest request) throws Exception {
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
    Object connect(String target) throws Exception {
        return new URL(target).openConnection().getInputStream();
    }
    void unrelated(MailSender sender, Archive archive, Message message) throws Exception {
        sender.send(message);
        archive.getInputStream();
    }
}
"""
    assert _fetch_lines("Fetcher.java", "java", source) == [5, 8, 11]


def test_csharp_fetch_chained_off_a_client_or_json_extension_is_hinted() -> None:
    source = b"""using System.Net.Http;
using System.Net.Http.Json;
public class Fetcher {
    private readonly HttpClient http;
    public Task<HttpResponseMessage> Chained(string url) => GetClient().GetAsync(url);
    public Task<Acme> Json(string url) => http.GetFromJsonAsync<Acme>(url);
    public Task<HttpResponseMessage> Post(Api api, string url) => api.PostAsJsonAsync(url, 1);
    public Task<string> Text(Api api, string url) => api.GetStringAsync(url);
    public Task<object> Cache(CacheStore cache, string key) => cache.GetAsync(key);
    public Task<object> Send(Bus bus, object message) => bus.SendAsync(message);
}
"""
    assert _fetch_lines("Fetcher.cs", "csharp", source) == [5, 6, 7, 8]


def test_go_do_on_a_client_receiver_or_bound_client_is_hinted() -> None:
    source = b"""package main
import "net/http"
type Service struct{ client *http.Client }
func direct(c *http.Client, r *http.Request) {
	c.Do(r)
}
func (s *Service) field(r *http.Request) {
	s.client.Do(r)
}
func built(r *http.Request) {
	client := newClient()
	client.Do(r)
}
func other(w Worker) {
	w.Do(1)
}
"""
    assert _fetch_lines("fetch.go", "go", source) == [5, 8, 12]
