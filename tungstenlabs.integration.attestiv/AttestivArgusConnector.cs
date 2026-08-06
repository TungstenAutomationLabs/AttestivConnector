using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

/*
 * tungstenlabs.integration.attestiv.AttestivArgusConnector
 *
 * End User License Agreement (EULA)
 *
 * IMPORTANT: PLEASE READ THIS AGREEMENT CAREFULLY BEFORE USING THIS SOFTWARE.
 *
 * 1. GRANT OF LICENSE: Tungsten Automation grants you a limited, non-exclusive,
 * non-transferable, and revocable license to use this software solely for the
 * purposes described in the documentation accompanying the software.
 *
 * 2. RESTRICTIONS: You may not sublicense, rent, lease, sell, distribute,
 * redistribute, assign, or otherwise transfer your rights to this software.
 * You may not reverse engineer, decompile, or disassemble this software,
 * except and only to the extent that such activity is expressly permitted by
 * applicable law notwithstanding this limitation.
 *
 * 3. COPYRIGHT: This software is protected by copyright laws and international
 * copyright treaties, as well as other intellectual property laws and treaties.
 *
 * 4. DISCLAIMER OF WARRANTY: THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * 5. TERMINATION: Without prejudice to any other rights, Tungsten Automation may
 * terminate this EULA if you fail to comply with the terms and conditions of this
 * EULA. In such event, you must destroy all copies of the software and all of its
 * component parts.
 *
 * 6. GOVERNING LAW: This agreement shall be governed by the laws of USA,
 * without regard to conflicts of laws principles. Any disputes arising hereunder shall
 * be subject to the exclusive jurisdiction of the courts of USA.
 *
 * 7. ENTIRE AGREEMENT: This EULA constitutes the entire agreement between you and
 * Tungsten Automation relating to the software and supersedes all prior or
 * contemporaneous understandings regarding such subject matter. No amendment to or
 * modification of this EULA will be binding unless made in writing and signed by
 * Tungsten Automation.
 *
 * Tungsten Automation
 * www.tungstenautomation.com
 * 2026
 */

namespace tungstenlabs.integration.attestiv
{
    

    /// <summary>
    /// OAuth2 client_credentials token response from Argus/Umbra auth.
    /// </summary>
    internal class DO_ArgusToken
    {
        [JsonProperty("access_token")] public string access_token { get; set; }
        [JsonProperty("token_type")] public string token_type { get; set; }
        [JsonProperty("expires_in")] public int expires_in { get; set; }
    }

    /// <summary>
    /// Accepted job response returned immediately on job submission (202).
    /// </summary>
    internal class DO_ArgusAcceptedJob
    {
        [JsonProperty("status")] public string status { get; set; }
        [JsonProperty("job_id")] public string job_id { get; set; }
        [JsonProperty("request_id")] public string request_id { get; set; }
        [JsonProperty("message")] public string message { get; set; }
        [JsonProperty("deduplicated")] public bool deduplicated { get; set; }
    }

    /// <summary>
    /// Proxy settings passed to proxy-enabled entry points.
    /// Mirrors DO_ProxySettings from RAI connector.
    /// </summary>
    public class DO_ArgusProxySettings
    {
        public string Url { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    /// <summary>
    /// Attestiv Argus V2 Connector.
    ///
    /// Provides forensic analysis of images, documents, video and audio
    /// via the Argus async job API (argus.api-us.attestiv.cloud).
    ///
    /// Runs alongside the existing V1 APIHelper class in the same DLL.
    /// V1 is fully preserved — this class is purely additive.
    ///
    /// OPEN QUESTION FOR ATTESTIV:
    ///   The 'flags' parameter for image analysis uses a string of letters
    ///   (e.g. "MSDRW"). The default value "MSDRW" was observed in the
    ///   Swagger UI. Please confirm:
    ///     1. What does each letter stand for? (M, S, D, R, W, F)
    ///     2. Are there other valid flags beyond these?
    ///     3. Is "MSDRW" the recommended default for standard use?
    ///   Until confirmed, "MSDRW" is used as the default in ATT-V2-FLAGS.
    /// </summary>
    public class AttestivArgusConnector
    {
        // =========================================================
        // Server Variable Constants
        // ATT-V2- prefix ensures no conflict with V1 variables
        // =========================================================
        public const string ATT_V2_BASE_URL = "ATT-V2-BASE-URL";
        public const string ATT_V2_TOKEN_URL = "ATT-V2-TOKEN-URL";
        public const string ATT_V2_ACCESS_TOKEN = "ATT-V2-ACCESS-TOKEN";
        public const string ATT_V2_CLIENT_ID = "ATT-V2-CLIENT-ID";
        public const string ATT_V2_CLIENT_SECRET = "ATT-V2-CLIENT-SECRET";
        public const string ATT_V2_MAX_RETRIES = "ATT-V2-MAX-RETRIES";
        public const string ATT_V2_FLAGS = "ATT-V2-FLAGS";

        // =========================================================
        // Terminal job statuses — polling stops on any of these
        // =========================================================
        private static readonly HashSet<string> TerminalStatuses =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "completed", "failed", "canceled" };

        // =========================================================
        // Instance state
        // =========================================================
        private IWebProxy _cachedProxy = null;
        private DO_ArgusToken AuthToken { get; set; }

        // =========================================================
        // Private: Read flags from TA server variable
        // Returns server variable value, or fallback if unavailable
        // =========================================================
        private string ResolveFlags(string taSessionId, string taSdkUrl, string overrideFlags)
        {
            if (!string.IsNullOrWhiteSpace(overrideFlags))
                return overrideFlags;

            try
            {
                var svHelper = new ServerVariableHelper();
                var sv = svHelper.GetServerVariables(taSessionId, taSdkUrl,
                    new List<string>() { ATT_V2_FLAGS });
                string val = sv[ATT_V2_FLAGS].Value;
                if (!string.IsNullOrWhiteSpace(val))
                    return val;
            }
            catch { }

            // OPEN QUESTION FOR ATTESTIV: confirm meaning of each flag letter
            // and whether "MSDRW" is the correct default. See class summary.
            return "MSDRW";
        }

        // =========================================================
        // Private: Read max retries from TA server variable
        // Returns server variable value, or fallback of 15
        // =========================================================
        private int ResolveMaxRetries(string taSessionId, string taSdkUrl, int overrideRetries)
        {
            if (overrideRetries > 0)
                return overrideRetries;

            try
            {
                var svHelper = new ServerVariableHelper();
                var sv = svHelper.GetServerVariables(taSessionId, taSdkUrl,
                    new List<string>() { ATT_V2_MAX_RETRIES });
                string val = sv[ATT_V2_MAX_RETRIES].Value;
                if (int.TryParse(val, out int parsed) && parsed > 0)
                    return parsed;
            }
            catch { }

            return 15;
        }

        // =========================================================
        // Private: Load non-sensitive server variables
        // clientId and clientSecret are NOT loaded here —
        // they are passed as parameters by the TA workflow
        // =========================================================
        private Dictionary<string, KeyValuePair<string, string>> LoadConfig(
            string taSessionId, string taSdkUrl)
        {
            var svHelper = new ServerVariableHelper();
            var vars = new List<string>()
            {
                ATT_V2_BASE_URL,
                ATT_V2_TOKEN_URL,
                ATT_V2_ACCESS_TOKEN
            };
            return svHelper.GetServerVariables(taSessionId, taSdkUrl, vars);
        }

        // =========================================================
        // Private: Refresh OAuth token from Argus/Umbra auth server
        // Mirrors RAI RefreshAuthToken — Basic auth + client_credentials
        // =========================================================
        private DO_ArgusToken RefreshAuthToken(string tokenUrl, string clientId, string clientSecret)
        {
            string credentials = string.Format("{0}:{1}", clientId, clientSecret);
            string base64Creds = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(tokenUrl);
            request.ContentType = "application/x-www-form-urlencoded";
            request.Accept = "application/json";
            request.Headers.Add(HttpRequestHeader.Authorization, "Basic " + base64Creds);
            request.Method = "POST";

            if (_cachedProxy != null)
                request.Proxy = _cachedProxy;

            byte[] bodyBytes = Encoding.UTF8.GetBytes("grant_type=client_credentials");
            request.ContentLength = bodyBytes.Length;

            using (var stream = request.GetRequestStream())
            {
                stream.Write(bodyBytes, 0, bodyBytes.Length);
                stream.Flush();
            }

            string responseText;
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
            {
                responseText = reader.ReadToEnd();
            }

            return JsonConvert.DeserializeObject<DO_ArgusToken>(responseText);
        }

        // =========================================================
        // Private: Read cached token from TA server variable
        // Mirrors RAI GetTokenFromTA
        // =========================================================
        private DO_ArgusToken GetTokenFromTA(string taSessionId, string taSdkUrl)
        {
            var svHelper = new ServerVariableHelper();
            var sv = svHelper.GetServerVariables(taSessionId, taSdkUrl,
                new List<string>() { ATT_V2_ACCESS_TOKEN });
            return new DO_ArgusToken() { access_token = sv[ATT_V2_ACCESS_TOKEN].Value };
        }

        // =========================================================
        // Private: Persist refreshed token back to TA server variable
        // =========================================================
        private void SaveTokenToTA(string taSessionId, string taSdkUrl)
        {
            var svHelper = new ServerVariableHelper();
            var dict = svHelper.GetServerVariables(taSessionId, taSdkUrl,
                new List<string>() { ATT_V2_ACCESS_TOKEN });
            dict[ATT_V2_ACCESS_TOKEN] = new KeyValuePair<string, string>(
                dict[ATT_V2_ACCESS_TOKEN].Key, AuthToken.access_token);
            svHelper.UpdateServerVariables(
                dict.ToDictionary(kvp => kvp.Value.Key, kvp => kvp.Value.Value),
                taSessionId, taSdkUrl);
        }

        // =========================================================
        // Private: Ensure valid token
        // Reads from TA cache first, refreshes only if empty/missing
        // Mirrors RAI EnsureValidToken exactly
        // =========================================================
        private void EnsureValidToken(string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            AuthToken = GetTokenFromTA(taSessionId, taSdkUrl);

            if (AuthToken == null || string.IsNullOrWhiteSpace(AuthToken.access_token))
            {
                AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);

                if (AuthToken == null || string.IsNullOrWhiteSpace(AuthToken.access_token))
                    throw new Exception("Unable to obtain a valid Auth Token from Attestiv Argus.");

                SaveTokenToTA(taSessionId, taSdkUrl);
            }
        }

        // =========================================================
        // Private: Build HttpClient with auth header and proxy if set
        // =========================================================
        private HttpClient BuildHttpClient()
        {
            var handler = new HttpClientHandler();
            if (_cachedProxy != null) { handler.Proxy = _cachedProxy; handler.UseProxy = true; }
            else { handler.UseProxy = false; }

            var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", AuthToken.access_token);
            return client;
        }

        // =========================================================
        // Private: Build proxy from DO_ArgusProxySettings
        // Mirrors RAI BuildProxyFromSettings
        // =========================================================
        private IWebProxy BuildProxyFromSettings(DO_ArgusProxySettings settings)
        {
            if (settings == null || string.IsNullOrWhiteSpace(settings.Url))
                return null;

            WebProxy proxy = new WebProxy(settings.Url)
            {
                BypassProxyOnLocal = false,
                BypassList = Array.Empty<string>()
            };

            if (!string.IsNullOrWhiteSpace(settings.Username))
                proxy.Credentials = new NetworkCredential(
                    settings.Username, settings.Password ?? string.Empty);
            else
                proxy.UseDefaultCredentials = true;

            return proxy;
        }

        // =========================================================
        // Private: Submit file as multipart/form-data to Argus
        // Handles 401/403 token refresh and 429/503 retryable errors
        // =========================================================
        private async Task<DO_ArgusAcceptedJob> SubmitFileAsync(
            HttpClient httpClient, string submitUrl,
            byte[] fileBytes, string fileName, string mimeType,
            Dictionary<string, string> additionalFields,
            string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            bool shouldRetry = false;
            do
            {
                shouldRetry = false;

                using (var content = new MultipartFormDataContent())
                {
                    var fileContent = new ByteArrayContent(fileBytes);
                    fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse(mimeType);
                    content.Add(fileContent, "file", fileName);

                    if (additionalFields != null)
                        foreach (var kv in additionalFields)
                            content.Add(new StringContent(kv.Value), kv.Key);

                    var response = await httpClient.PostAsync(submitUrl, content)
                        .ConfigureAwait(false);

                    if (response.StatusCode == HttpStatusCode.Unauthorized ||
                        response.StatusCode == HttpStatusCode.Forbidden)
                    {
                        AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);
                        SaveTokenToTA(taSessionId, taSdkUrl);
                        httpClient.DefaultRequestHeaders.Authorization =
                            new AuthenticationHeaderValue("Bearer", AuthToken.access_token);
                        shouldRetry = true;
                        continue;
                    }

                    // Retryable server-side errors: 429 queue full, 503 temp storage
                    if (response.StatusCode == (HttpStatusCode)429 ||
                        response.StatusCode == HttpStatusCode.ServiceUnavailable)
                    {
                        await Task.Delay(5000).ConfigureAwait(false);
                        shouldRetry = true;
                        continue;
                    }

                    response.EnsureSuccessStatusCode();

                    string responseText = await response.Content.ReadAsStringAsync()
                        .ConfigureAwait(false);
                    return JsonConvert.DeserializeObject<DO_ArgusAcceptedJob>(responseText);
                }
            } while (shouldRetry);

            throw new Exception("Failed to submit file to Argus after retries.");
        }

        // =========================================================
        // Private: Submit URL job as JSON to Argus
        // =========================================================
        private async Task<DO_ArgusAcceptedJob> SubmitUrlAsync(
            HttpClient httpClient, string submitUrl, string body,
            string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            bool shouldRetry = false;
            do
            {
                shouldRetry = false;

                var requestContent = new StringContent(body, Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync(submitUrl, requestContent)
                    .ConfigureAwait(false);

                if (response.StatusCode == HttpStatusCode.Unauthorized ||
                    response.StatusCode == HttpStatusCode.Forbidden)
                {
                    AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);
                    SaveTokenToTA(taSessionId, taSdkUrl);
                    httpClient.DefaultRequestHeaders.Authorization =
                        new AuthenticationHeaderValue("Bearer", AuthToken.access_token);
                    shouldRetry = true;
                    continue;
                }

                if (response.StatusCode == (HttpStatusCode)429 ||
                    response.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    await Task.Delay(5000).ConfigureAwait(false);
                    shouldRetry = true;
                    continue;
                }

                response.EnsureSuccessStatusCode();

                string responseText = await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false);
                return JsonConvert.DeserializeObject<DO_ArgusAcceptedJob>(responseText);

            } while (shouldRetry);

            throw new Exception("Failed to submit URL job to Argus after retries.");
        }

        // =========================================================
        // Private: Poll single job until terminal state
        // Mirrors RAI FetchResultsAsync — backoff, inline token refresh
        // =========================================================
        private async Task<string> PollJobUntilCompleteAsync(
            string baseUrl, string jobId, int maxAttempts,
            string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            var handler = new HttpClientHandler();
            if (_cachedProxy != null) { handler.Proxy = _cachedProxy; handler.UseProxy = true; }
            else { handler.UseProxy = false; }

            using (var httpClient = new HttpClient(handler))
            {
                httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", AuthToken.access_token);

                string requestUri = $"{baseUrl}/api/v1/jobs/{jobId}";
                int attempt = 0;
                int delayMs = 4000;
                string result = null;

                while (attempt <= maxAttempts && string.IsNullOrWhiteSpace(result))
                {
                    try
                    {
                        await Task.Delay(delayMs).ConfigureAwait(false);

                        var response = await httpClient.GetAsync(requestUri).ConfigureAwait(false);

                        if (response.StatusCode == HttpStatusCode.Unauthorized ||
                            response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);
                            SaveTokenToTA(taSessionId, taSdkUrl);
                            httpClient.DefaultRequestHeaders.Authorization =
                                new AuthenticationHeaderValue("Bearer", AuthToken.access_token);
                            delayMs += 1000 * attempt;
                            attempt++;
                            continue;
                        }

                        response.EnsureSuccessStatusCode();

                        string content = await response.Content.ReadAsStringAsync()
                            .ConfigureAwait(false);
                        var json = JObject.Parse(content);
                        string status = json["status"]?.ToString() ?? "";

                        if (TerminalStatuses.Contains(status))
                            result = content;
                    }
                    catch (HttpRequestException ex) when (IsProxyAuthError(ex))
                    {
                        throw new Exception(
                            "Proxy authentication failed (HTTP 407). Please verify proxy settings.", ex);
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt >= maxAttempts)
                            throw new Exception(
                                $"Argus polling failed after {attempt} attempts: {ex.Message}", ex);
                    }

                    delayMs += 1000 * attempt;
                    attempt++;
                }

                if (string.IsNullOrWhiteSpace(result))
                    throw new Exception(
                        $"Argus job {jobId} did not reach a terminal state after {maxAttempts} attempts.");

                return result;
            }
        }

        // =========================================================
        // Private: Poll multiple jobs via batch_status endpoint
        // More efficient than polling each job individually
        // =========================================================
        private async Task<string> PollJobsBatchAsync(
            string baseUrl, List<string> jobIds, int maxAttempts,
            string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            var handler = new HttpClientHandler();
            if (_cachedProxy != null) { handler.Proxy = _cachedProxy; handler.UseProxy = true; }
            else { handler.UseProxy = false; }

            using (var httpClient = new HttpClient(handler))
            {
                httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", AuthToken.access_token);

                string requestUri = $"{baseUrl}/api/v1/jobs/batch_status";
                int attempt = 0;
                int delayMs = 4000;
                var pendingJobIds = new List<string>(jobIds);
                var completedResults = new Dictionary<string, JObject>();

                while (attempt <= maxAttempts && pendingJobIds.Count > 0)
                {
                    try
                    {
                        await Task.Delay(delayMs).ConfigureAwait(false);

                        string body = JsonConvert.SerializeObject(new { job_ids = pendingJobIds });
                        var requestContent = new StringContent(body, Encoding.UTF8, "application/json");
                        var response = await httpClient.PostAsync(requestUri, requestContent)
                            .ConfigureAwait(false);

                        if (response.StatusCode == HttpStatusCode.Unauthorized ||
                            response.StatusCode == HttpStatusCode.Forbidden)
                        {
                            AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);
                            SaveTokenToTA(taSessionId, taSdkUrl);
                            httpClient.DefaultRequestHeaders.Authorization =
                                new AuthenticationHeaderValue("Bearer", AuthToken.access_token);
                            delayMs += 1000 * attempt;
                            attempt++;
                            continue;
                        }

                        response.EnsureSuccessStatusCode();

                        string content = await response.Content.ReadAsStringAsync()
                            .ConfigureAwait(false);
                        var batchJson = JObject.Parse(content);
                        var results = batchJson["results"] as JArray;
                        var stillPending = new List<string>();

                        if (results != null)
                        {
                            foreach (var item in results)
                            {
                                string jid = item["job_id"]?.ToString();
                                bool found = item["found"]?.Value<bool>() ?? false;
                                string status = item["job"]?["status"]?.ToString() ?? "";

                                if (!found)
                                {
                                    completedResults[jid] = JObject.FromObject(new
                                    {
                                        job_id = jid,
                                        status = "failed",
                                        error = "Job not found in Argus."
                                    });
                                }
                                else if (TerminalStatuses.Contains(status))
                                {
                                    completedResults[jid] = (JObject)item["job"];
                                }
                                else
                                {
                                    stillPending.Add(jid);
                                }
                            }
                            pendingJobIds = stillPending;
                        }
                    }
                    catch (HttpRequestException ex) when (IsProxyAuthError(ex))
                    {
                        throw new Exception(
                            "Proxy authentication failed (HTTP 407). Please verify proxy settings.", ex);
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt >= maxAttempts)
                            throw new Exception(
                                $"Argus batch polling failed after {attempt} attempts: {ex.Message}", ex);
                    }

                    delayMs += 1000 * attempt;
                    attempt++;
                }

                if (pendingJobIds.Count > 0)
                    throw new Exception(
                        $"Argus batch: {pendingJobIds.Count} job(s) did not complete after " +
                        $"{maxAttempts} attempts. Pending: {string.Join(", ", pendingJobIds)}");

                return JsonConvert.SerializeObject(
                    completedResults.Values.ToList(), Formatting.Indented);
            }
        }

        // =========================================================
        // Private: Fetch file bytes + filename from KTA
        // =========================================================
        private KeyValuePair<string, byte[]> GetKTADocumentFile(
            string docID, string ktaSdkUrl, string sessionID)
        {
            byte[] file = new byte[1];
            byte[] buffer = new byte[4096];

            try
            {
                string ktaGetDocument = ktaSdkUrl + "/CaptureDocumentService.svc/json/GetDocument";
                HttpClient httpClient = new HttpClient();
                var getRequestPayload = new { sessionId = sessionID, documentId = docID };
                var getRequestContent = new StringContent(
                    JsonConvert.SerializeObject(getRequestPayload), Encoding.UTF8, "application/json");
                var getResponse = httpClient.PostAsync(ktaGetDocument, getRequestContent)
                    .GetAwaiter().GetResult();

                if (!getResponse.IsSuccessStatusCode)
                    throw new Exception(
                        $"Error fetching KTA document metadata: {getResponse.ReasonPhrase}");

                var getResponseContent = getResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var getResponseJson = JObject.Parse(getResponseContent);
                string filename = getResponseJson["d"]?["FileName"]?.ToString();

                string ktaGetFile = ktaSdkUrl + "/CaptureDocumentService.svc/json/GetDocumentFile2";
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(ktaGetFile);
                httpWebRequest.ContentType = "application/json";
                httpWebRequest.Method = "POST";

                using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
                {
                    string json = "{\"sessionId\":\"" + sessionID +
                        "\",\"reportingData\": {\"Station\": \"\", \"MarkCompleted\": false }," +
                        "\"documentId\":\"" + docID +
                        "\", \"documentFileOptions\": { \"FileType\": \"\", \"IncludeAnnotations\": 0 } }";
                    streamWriter.Write(json);
                    streamWriter.Flush();
                }

                HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();

                using (Stream responseStream = httpWebResponse.GetResponseStream())
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = responseStream.Read(buffer, 0, buffer.Length);
                        memoryStream.Write(buffer, 0, count);
                    } while (count != 0);

                    file = memoryStream.ToArray();
                }

                return new KeyValuePair<string, byte[]>(filename, file);
            }
            catch (Exception ex)
            {
                throw new Exception("Exception GetKTADocumentFile: " + ex.ToString(), ex);
            }
        }

        // =========================================================
        // Private: MIME type detection — extension + byte signature
        // Extended from V1 to include TIFF and HEIC (v1.2.5 / v1.2.6)
        // =========================================================
        private static string GetMimeType(string fileExtension, byte[] fileBytes)
        {
            if (!string.IsNullOrWhiteSpace(fileExtension))
            {
                if (!fileExtension.StartsWith(".")) fileExtension = "." + fileExtension;
                try
                {
                    string mime = System.Web.MimeMapping.GetMimeMapping(fileExtension);
                    if (!string.IsNullOrWhiteSpace(mime) &&
                        !mime.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase))
                        return mime;
                }
                catch { }
            }

            if (fileBytes == null || fileBytes.Length < 4)
                return "application/octet-stream";

            // JPEG: FF D8
            if (fileBytes[0] == 0xFF && fileBytes[1] == 0xD8)
                return "image/jpeg";

            // PNG: 89 50 4E 47
            if (fileBytes[0] == 0x89 && fileBytes[1] == 0x50 &&
                fileBytes[2] == 0x4E && fileBytes[3] == 0x47)
                return "image/png";

            // GIF: 47 49 46
            if (fileBytes[0] == 0x47 && fileBytes[1] == 0x49 && fileBytes[2] == 0x46)
                return "image/gif";

            // TIFF little-endian: 49 49 2A 00
            if (fileBytes[0] == 0x49 && fileBytes[1] == 0x49 &&
                fileBytes[2] == 0x2A && fileBytes[3] == 0x00)
                return "image/tiff";

            // TIFF big-endian: 4D 4D 00 2A
            if (fileBytes[0] == 0x4D && fileBytes[1] == 0x4D &&
                fileBytes[2] == 0x00 && fileBytes[3] == 0x2A)
                return "image/tiff";

            // PDF: 25 50 44 46
            if (fileBytes[0] == 0x25 && fileBytes[1] == 0x50 &&
                fileBytes[2] == 0x44 && fileBytes[3] == 0x46)
                return "application/pdf";

            // HEIC: ftyp box — bytes 4-7 contain 'ftyp', bytes 8-11 contain brand
            // Common HEIC brands: heic, heix, hevc, mif1
            // Added in Argus v1.2.5
            if (fileBytes.Length >= 12)
            {
                string ftyp = Encoding.ASCII.GetString(fileBytes, 4, 4);
                string brand = Encoding.ASCII.GetString(fileBytes, 8, 4);
                if (ftyp == "ftyp" &&
                    (brand.StartsWith("hei") || brand.StartsWith("mif") || brand.StartsWith("hev")))
                    return "image/heic";
            }

            return "application/octet-stream";
        }

        // =========================================================
        // Private: File extension from filename
        // =========================================================
        private static string GetFileExtension(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return string.Empty;
            int lastDot = fileName.LastIndexOf('.');
            return (lastDot == -1 || lastDot == fileName.Length - 1)
                ? string.Empty
                : fileName.Substring(lastDot + 1);
        }

        // =========================================================
        // Private: Proxy auth error detection
        // Mirrors RAI IsProxyAuthError
        // =========================================================
        private static bool IsProxyAuthError(HttpRequestException ex)
        {
            var webEx = ex.InnerException as WebException;
            var response = webEx?.Response as HttpWebResponse;
            return response?.StatusCode == HttpStatusCode.ProxyAuthenticationRequired;
        }

        // =========================================================
        // Private: KTA folder helpers
        // =========================================================
        private string GetKTAFolder(string folderID, string ktaSdkUrl, string sessionID)
        {
            try
            {
                string ktaGetFolder = ktaSdkUrl +
                    "/CaptureDocumentService.svc/json/GetFolderFieldValue";
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ktaGetFolder);
                request.ContentType = "application/json";
                request.Method = "POST";

                using (var writer = new StreamWriter(request.GetRequestStream()))
                {
                    string json = "{\"sessionId\":\"" + sessionID +
                        "\",\"folderId\":\"" + folderID +
                        "\",\"reportingData\": {\"Station\": \"\",\"MarkCompleted\": false}," +
                        "\"fieldIdentity\": {\"Id\": \"8A3DFE7947444402A4FB47BD0CA2ADD5\"," +
                        "\"Table Row\": 0,\"Table Column\": 0,\"Name\": \"\"}";
                    writer.Write(json);
                    writer.Flush();
                }

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                using (var reader = new StreamReader(response.GetResponseStream()))
                    return reader.ReadToEnd();
            }
            catch
            {
                return string.Empty;
            }
        }

        private string[] GetFirstColumn(string jsonString)
        {
            JObject jsonObject = JObject.Parse(jsonString);
            JArray valueArray = (JArray)jsonObject["d"]["Value"];
            string[] firstColumn = new string[valueArray.Count];
            for (int i = 0; i < valueArray.Count; i++)
                firstColumn[i] = valueArray[i][0].ToString();
            return firstColumn;
        }

        // =========================================================
        // Public: Initialize
        // Validates credentials by minting first token and stores
        // all config in TA server variables.
        // Call once during setup or when credentials change.
        // clientId and clientSecret passed as parameters — not stored
        // permanently here, only the minted token is cached.
        // =========================================================
        /// <summary>
        /// Validates Argus V2 credentials and stores config in TotalAgility server variables.
        /// Call once during initial setup or when credentials change.
        /// </summary>
        /// <param name="baseUrl">Argus base URL e.g. https://argus.api-us.attestiv.cloud</param>
        /// <param name="tokenUrl">Umbra OAuth token URL</param>
        /// <param name="clientId">OAuth client ID — passed from TA workflow</param>
        /// <param name="clientSecret">OAuth client secret — passed from TA workflow</param>
        /// <param name="taSessionId">TotalAgility Session ID</param>
        /// <param name="taSdkUrl">TotalAgility SDK URL</param>
        public bool Initialize(string baseUrl, string tokenUrl, string clientId, string clientSecret,
            string taSessionId, string taSdkUrl)
        {
            _cachedProxy = null;

            AuthToken = RefreshAuthToken(tokenUrl, clientId, clientSecret);
            if (AuthToken == null || string.IsNullOrWhiteSpace(AuthToken.access_token))
                throw new Exception(
                    "Unable to obtain a valid Auth Token from Attestiv Argus during Initialize.");

            var svHelper = new ServerVariableHelper();
            var vars = new List<string>()
            {
                ATT_V2_BASE_URL, ATT_V2_TOKEN_URL, ATT_V2_ACCESS_TOKEN
            };
            var dict = svHelper.GetServerVariables(taSessionId, taSdkUrl, vars);

            dict[ATT_V2_BASE_URL] = new KeyValuePair<string, string>(
                dict[ATT_V2_BASE_URL].Key, baseUrl);
            dict[ATT_V2_TOKEN_URL] = new KeyValuePair<string, string>(
                dict[ATT_V2_TOKEN_URL].Key, tokenUrl);
            dict[ATT_V2_ACCESS_TOKEN] = new KeyValuePair<string, string>(
                dict[ATT_V2_ACCESS_TOKEN].Key, AuthToken.access_token);

            svHelper.UpdateServerVariables(
                dict.ToDictionary(kvp => kvp.Value.Key, kvp => kvp.Value.Value),
                taSessionId, taSdkUrl);

            return true;
        }

        // =========================================================
        // Public: AnalyzeImage (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility document for Argus image forensic analysis.
        /// Supports JPG, PNG, TIFF, HEIC.
        /// </summary>
        /// <param name="taDocId">TotalAgility Document ID</param>
        /// <param name="taSessionId">TotalAgility Session ID</param>
        /// <param name="taSdkUrl">TotalAgility SDK URL</param>
        /// <param name="clientId">OAuth client ID — passed from TA workflow</param>
        /// <param name="clientSecret">OAuth client secret — passed from TA workflow</param>
        /// <param name="flags">
        /// Analysis flags. Null/empty = read from ATT-V2-FLAGS server variable.
        /// OPEN QUESTION FOR ATTESTIV: confirm meaning of each flag letter in "MSDRW".
        /// </param>
        /// <param name="numberOfRetries">
        /// Max polling attempts. 0 = read from ATT-V2-MAX-RETRIES server variable.
        /// </param>
        public string AnalyzeImage(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string flags = null, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedFlags = ResolveFlags(taSessionId, taSdkUrl, flags);
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string>
            {
                { "flags",      resolvedFlags },
                { "request_id", taDocId }
            };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/image",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeImage1 (WITH PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility document for Argus image forensic analysis via proxy.
        /// </summary>
        public string AnalyzeImage1(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret, DO_ArgusProxySettings proxySettings,
            string flags = null, int numberOfRetries = 0)
        {
            _cachedProxy = BuildProxyFromSettings(proxySettings);
            if (_cachedProxy == null)
                throw new ArgumentException("Valid proxy settings are required for AnalyzeImage1.");

            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedFlags = ResolveFlags(taSessionId, taSdkUrl, flags);
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string>
            {
                { "flags",      resolvedFlags },
                { "request_id", taDocId }
            };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/image",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeImageByUrl (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a publicly accessible image URL for Argus forensic analysis.
        /// Avoids downloading file from KTA when image is already accessible by URL.
        /// </summary>
        public string AnalyzeImageByUrl(string imageUrl, string requestId,
            string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string flags = null, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedFlags = ResolveFlags(taSessionId, taSdkUrl, flags);
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            string body = JsonConvert.SerializeObject(new
            {
                url = imageUrl,
                flags = resolvedFlags,
                request_id = requestId
            });

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitUrlAsync(httpClient, $"{baseUrl}/api/v1/jobs/image/url",
                    body, tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeImageBulk (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits all images in a TotalAgility folder for Argus forensic analysis.
        /// Uses batch status polling for efficient multi-job tracking.
        /// </summary>
        public string AnalyzeImageBulk(string taFolderId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string flags = null, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedFlags = ResolveFlags(taSessionId, taSdkUrl, flags);
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            string folderJson = GetKTAFolder(taFolderId, taSdkUrl, taSessionId);
            string[] docIds = GetFirstColumn(folderJson);
            var jobIds = new List<string>();

            using (var httpClient = BuildHttpClient())
            {
                foreach (string docId in docIds)
                {
                    var ktaFile = GetKTADocumentFile(docId, taSdkUrl, taSessionId);
                    if (ktaFile.Value == null || ktaFile.Value.Length == 0)
                        throw new ArgumentException($"File for document {docId} is null or empty.");

                    string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);
                    var fields = new Dictionary<string, string>
                    {
                        { "flags",      resolvedFlags },
                        { "request_id", docId }
                    };

                    var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/image",
                        ktaFile.Value, ktaFile.Key, mime, fields,
                        tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                        .GetAwaiter().GetResult();

                    jobIds.Add(accepted.job_id);
                }

                return PollJobsBatchAsync(baseUrl, jobIds, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeDocument (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility document (e.g. PDF) for Argus document forensic analysis.
        /// V2 document analysis achieves ~99% precision. New in V2 — not in V1.
        /// </summary>
        /// <param name="docAnalysisMode">
        /// Analysis mode flags, default "MSDC".
        /// Null/empty = read from ATT-V2-FLAGS server variable.
        /// OPEN QUESTION FOR ATTESTIV: confirm valid doc_analysis_mode values.
        /// </param>
        public string AnalyzeDocument(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string docAnalysisMode = null, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            // Note: document uses docAnalysisMode not flags — default "MSDC"
            string resolvedMode = string.IsNullOrWhiteSpace(docAnalysisMode) ? "MSDC" : docAnalysisMode;
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string>
            {
                { "doc_analysis_mode", resolvedMode },
                { "request_id",        taDocId }
            };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/document",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeDocument1 (WITH PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility document for Argus document forensic analysis via proxy.
        /// </summary>
        public string AnalyzeDocument1(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret, DO_ArgusProxySettings proxySettings,
            string docAnalysisMode = null, int numberOfRetries = 0)
        {
            _cachedProxy = BuildProxyFromSettings(proxySettings);
            if (_cachedProxy == null)
                throw new ArgumentException("Valid proxy settings are required for AnalyzeDocument1.");

            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedMode = string.IsNullOrWhiteSpace(docAnalysisMode) ? "MSDC" : docAnalysisMode;
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string>
            {
                { "doc_analysis_mode", resolvedMode },
                { "request_id",        taDocId }
            };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/document",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeDocumentByUrl (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a publicly accessible document URL for Argus forensic analysis.
        /// New in V2 — not available in V1.
        /// </summary>
        public string AnalyzeDocumentByUrl(string documentUrl, string requestId,
            string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string docAnalysisMode = null, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            string resolvedMode = string.IsNullOrWhiteSpace(docAnalysisMode) ? "MSDC" : docAnalysisMode;
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            string body = JsonConvert.SerializeObject(new
            {
                url = documentUrl,
                doc_analysis_mode = resolvedMode,
                request_id = requestId
            });

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitUrlAsync(httpClient, $"{baseUrl}/api/v1/jobs/document/url",
                    body, tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeVideo (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility video document for Argus video forensic analysis.
        /// New in V2 — not available in V1.
        /// Default retries higher (30) as video jobs take longer to complete.
        /// </summary>
        public string AnalyzeVideo(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            // Video jobs take longer — use 30 as fallback if TA variable not set
            int resolvedRetries = numberOfRetries > 0 ? numberOfRetries
                : ResolveMaxRetries(taSessionId, taSdkUrl, 0);
            if (resolvedRetries < 30) resolvedRetries = 30;

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string> { { "request_id", taDocId } };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/video",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeVideoByUrl (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a video URL (including YouTube) for Argus forensic analysis.
        /// New in V2 — not available in V1.
        /// </summary>
        public string AnalyzeVideoByUrl(string videoUrl, string requestId,
            string taSessionId, string taSdkUrl,
            string clientId, string clientSecret, int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            int resolvedRetries = numberOfRetries > 0 ? numberOfRetries
                : ResolveMaxRetries(taSessionId, taSdkUrl, 0);
            if (resolvedRetries < 30) resolvedRetries = 30;

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            string body = JsonConvert.SerializeObject(new
            {
                url = videoUrl,
                request_id = requestId
            });

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitUrlAsync(httpClient, $"{baseUrl}/api/v1/jobs/video/url",
                    body, tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: AnalyzeAudio (NO PROXY)
        // =========================================================
        /// <summary>
        /// Submits a TotalAgility audio document for Argus audio forensic analysis.
        /// Detects AI-generated/synthetic voice. New in V2 — not available in V1.
        /// </summary>
        /// <param name="audioAnalysisMode">
        /// Analysis mode, default "TPA".
        /// OPEN QUESTION FOR ATTESTIV: confirm valid audio_analysis_mode values.
        /// </param>
        public string AnalyzeAudio(string taDocId, string taSessionId, string taSdkUrl,
            string clientId, string clientSecret,
            string audioAnalysisMode = "TPA", int numberOfRetries = 0)
        {
            _cachedProxy = null;
            var sv = LoadConfig(taSessionId, taSdkUrl);
            string baseUrl = sv[ATT_V2_BASE_URL].Value;
            string tokenUrl = sv[ATT_V2_TOKEN_URL].Value;
            int resolvedRetries = ResolveMaxRetries(taSessionId, taSdkUrl, numberOfRetries);

            EnsureValidToken(tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl);

            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            string mime = GetMimeType(GetFileExtension(ktaFile.Key), ktaFile.Value);

            var fields = new Dictionary<string, string>
            {
                { "audio_analysis_mode", audioAnalysisMode },
                { "request_id",          taDocId }
            };

            using (var httpClient = BuildHttpClient())
            {
                var accepted = SubmitFileAsync(httpClient, $"{baseUrl}/api/v1/jobs/audio",
                    ktaFile.Value, ktaFile.Key, mime, fields,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();

                return PollJobUntilCompleteAsync(baseUrl, accepted.job_id, resolvedRetries,
                    tokenUrl, clientId, clientSecret, taSessionId, taSdkUrl)
                    .GetAwaiter().GetResult();
            }
        }

        // =========================================================
        // Public: ExtractResultScore
        // Parses Argus V2 job result into a simplified structure.
        // =========================================================
        /// <summary>
        /// Extracts and simplifies the Argus V2 analysis result from a completed job JSON.
        /// Returns clean JSON with verdict, score, AI contextual summary and per-module breakdown.
        /// </summary>
        public string ExtractResultScore(string jobResultJson)
        {
            var jobJson = JObject.Parse(jobResultJson);
            var analysis = jobJson["analysis"];

            if (analysis == null)
                throw new ArgumentException(
                    "Invalid Argus job result: 'analysis' field is missing.");

            string status = jobJson["status"]?.ToString() ?? "";
            if (!status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(
                    $"Job has not completed successfully. Status: {status}");

            var simplified = new JObject
            {
                ["jobId"] = jobJson["job_id"],
                ["requestId"] = jobJson["request_id"],
                ["status"] = jobJson["status"],
                ["acceptedAt"] = jobJson["accepted_at"],
                ["completedAt"] = jobJson["completed_at"],
                ["type"] = analysis["type"],
                ["verdict"] = analysis["verdict"],    // REAL / FAKE / AMBIGUOUS / ERROR
                ["totalScore"] = analysis["total_score"],
                ["totalLen"] = analysis["total_len"],
                ["summary"] = analysis["summary"],    // AI contextual summary — new in V2
                ["modules"] = new JArray()
            };

            var modules = analysis["modules"] as JObject;
            if (modules != null)
            {
                foreach (var module in modules)
                {
                    var moduleObject = new JObject
                    {
                        ["model"] = module.Key,
                        ["score"] = module.Value["score"],
                        ["reasoning"] = module.Value["reasoning"]
                    };
                    ((JArray)simplified["modules"]).Add(moduleObject);
                }
            }

            return JsonConvert.SerializeObject(simplified, Formatting.Indented);
        }

        // =========================================================
        // Public: ExtractBulkResultScore
        // Parses Argus V2 bulk job results (from AnalyzeImageBulk).
        // =========================================================
        /// <summary>
        /// Extracts and simplifies bulk Argus V2 analysis results.
        /// Returns JSON with HasInvalidDocuments flag and per-file scores/verdicts/summaries.
        /// </summary>
        public string ExtractBulkResultScore(string bulkJobResultJson, int maxTamperScore)
        {
            var jobArray = JArray.Parse(bulkJobResultJson);
            var results = new List<object>();
            bool hasInvalidDocs = false;

            foreach (var job in jobArray)
            {
                string jobId = job["job_id"]?.ToString();
                string status = job["status"]?.ToString() ?? "";
                var analysis = job["analysis"];

                if (analysis == null ||
                    !status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new
                    {
                        JobId = jobId,
                        Status = status,
                        Error = job["error"]?.ToString() ?? "Analysis not available."
                    });
                    continue;
                }

                int totalScore = analysis["total_score"]?.Value<int>() ?? 0;
                string verdict = analysis["verdict"]?.ToString() ?? "";
                string summary = analysis["summary"]?.ToString() ?? "";

                if (totalScore > maxTamperScore)
                    hasInvalidDocs = true;

                results.Add(new
                {
                    JobId = jobId,
                    TotalScore = totalScore,
                    Verdict = verdict,
                    Summary = summary
                });
            }

            return JsonConvert.SerializeObject(new
            {
                HasInvalidDocuments = hasInvalidDocs,
                Records = results
            }, Formatting.Indented);
        }

        // =========================================================
        // Public: IsFileCompatible
        // Checks file meets Argus V2 minimum requirements.
        // Extended from V1 to include TIFF and HEIC.
        // =========================================================
        /// <summary>
        /// Checks whether a TotalAgility document meets Argus V2 minimum file requirements.
        /// Supported types: JPG, PNG, TIFF, HEIC (images) and PDF (documents).
        /// </summary>
        public bool IsFileCompatible(string taDocId, string taSessionId, string taSdkUrl,
            float horizontalMin = 640f, float verticalMin = 480f)
        {
            var ktaFile = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
            byte[] file = ktaFile.Value;

            if (file == null || file.Length == 0)
                return false;

            string mime = GetMimeType(GetFileExtension(ktaFile.Key), file);

            // PDF — no resolution check needed
            if (mime == "application/pdf")
                return true;

            var supportedImageTypes = new HashSet<string>
            {
                "image/jpeg", "image/png", "image/tiff", "image/heic"
            };

            if (!supportedImageTypes.Contains(mime))
                return false;

            try
            {
                using (var ms = new MemoryStream(file))
                using (var image = System.Drawing.Image.FromStream(ms))
                {
                    return image.Height >= horizontalMin && image.Width >= verticalMin;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}