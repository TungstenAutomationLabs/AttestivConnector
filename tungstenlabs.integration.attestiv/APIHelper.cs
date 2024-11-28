using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;
using Newtonsoft.Json;

namespace tungstenlabs.integration.attestiv
{
    public class APIHelper
    {
        public const string ATT_ACCESS_TOKEN = "ATT-ACCESS-TOKEN";
        public const string ATT_API_URL = "ATT-API-URL";
        public const string ATT_USER_ID = "ATT-USER-ID";
        public const string ATT_PSWD_ID = "ATT-PSWD-ID";

        /// <summary>
        /// Authenticates with Attestiv API using JWT and retrieves an access token, then saves all values in TA's server variables.
        /// </summary>
        public bool Initialize(string baseApiUrl, string userId, string pswd, string taSessionId, string taSdkUrl, bool isPswdHashed)
        {
            string password = pswd;

            // Encode the password using SHA-256
            if (!isPswdHashed)
                password = ComputeSha256Hash(pswd);

            string tokenUrl = $"{baseApiUrl}/users/login";

            string json = $"{{ \"username\": \"{userId}\", \"password\": \"{password}\" }}"; 

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(tokenUrl);
            request.Method = "POST";
            request.ContentType = "application/json";

            using (StreamWriter writer = new StreamWriter(request.GetRequestStream()))
            {
                writer.Write(json);
            }

            string responseContent;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    responseContent = reader.ReadToEnd();
                }
            }

            var jsonData = JObject.Parse(responseContent);
            var accessToken = jsonData["accessToken"]?.ToString();
            List<string> vars = new List<string>() { ATT_ACCESS_TOKEN, ATT_API_URL, ATT_USER_ID, ATT_PSWD_ID };

            ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
            var dict = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, vars);
            dict[ATT_ACCESS_TOKEN] = new KeyValuePair<string, string>(dict[ATT_ACCESS_TOKEN].Key, accessToken);
            dict[ATT_API_URL] = new KeyValuePair<string, string>(dict[ATT_API_URL].Key, baseApiUrl);
            dict[ATT_USER_ID] = new KeyValuePair<string, string>(dict[ATT_USER_ID].Key, userId);
            dict[ATT_PSWD_ID] = new KeyValuePair<string, string>(dict[ATT_PSWD_ID].Key, password);

            Dictionary<string, string> newDict = dict.ToDictionary(kvp => kvp.Value.Key, kvp => kvp.Value.Value);
            serverVariableHelper.UpdateServerVariables(newDict, taSessionId, taSdkUrl);

            return true;

        }

        /// <summary>
        /// Authenticates with Salesforce using OAuth2 and retrieves an access token.
        /// </summary>
        public bool Authenticate(string taSessionId, string taSdkUrl)
        {
            List<string> vars = new List<string>() { ATT_ACCESS_TOKEN, ATT_API_URL, ATT_USER_ID, ATT_PSWD_ID };

            ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
            var sv = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, vars);

            return Initialize(sv[ATT_API_URL].Value, sv[ATT_USER_ID].Value, sv[ATT_PSWD_ID].Value, taSessionId, taSdkUrl, true);
        }

        /// <summary>
        /// Uses the resulting JSON to extract the tamperscore for each file.
        /// </summary>
        public string ExtractImageAndTamperScore(string jsonInput, int maxTamperScore)
        {
            // Parse the input JSON into a JArray
            JArray inputArray = JArray.Parse(jsonInput);

            // Create a list to hold simplified results
            var results = new List<object>();
            bool hasInvalidDocuments = false;

            // Iterate through each item in the array
            foreach (var item in inputArray)
            {
                var detectTamperingResult = item["detect_tampering_result"];
                if (detectTamperingResult != null)
                {
                    var image = detectTamperingResult["image"]?.ToString();
                    var tamperScoreString = detectTamperingResult["tamperScore"]?.ToString();

                    if (!string.IsNullOrEmpty(image) && !string.IsNullOrEmpty(tamperScoreString))
                    {
                        int tamperScore = int.Parse(tamperScoreString);

                        // Check if tamperScore exceeds maxTamperScore
                        if (tamperScore > maxTamperScore)
                        {
                            hasInvalidDocuments = true;
                        }

                        results.Add(new
                        {
                            Image = image,
                            TamperScore = tamperScore
                        });
                    }
                }
            }

            // Create the final result including the flag
            var finalResult = new
            {
                HasInvalidDocuments = hasInvalidDocuments,
                Records = results
            };

            // Convert the final result to a JSON string
            return JsonConvert.SerializeObject(finalResult, Formatting.Indented);
        }


        /// <summary>
        /// Communicates with Attestiv API to call their "Analyze Image" method.
        /// </summary>
        /// <param name="taDocId">TotalAgility Document ID; this can only be an image file</param>
        /// <param name="taSessionId">TA SessionID.</param>
        /// <param name="taSdkUrl">TA SDK URL.</param>
        public string AnalyzeImage(string taDocId, string taSessionId, string taSdkUrl)
        {
            int maxRetries = 3;
            int count = 0;
            bool shouldRetry;

            List<string> vars = new List<string>() { ATT_ACCESS_TOKEN, ATT_API_URL };

            do
            {
                shouldRetry = false;
                ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
                var sv = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, vars);

                KeyValuePair<string,byte[]> dict = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);
                byte[] payload = dict.Value;

                try
                {
                    using (var client = new HttpClient())
                    {
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", sv[ATT_ACCESS_TOKEN].Value);

                        using (var content = new MultipartFormDataContent())
                        {
                            var imageContent = new ByteArrayContent(payload);
                            imageContent.Headers.ContentType = MediaTypeHeaderValue.Parse(GetMimeType(GetFileExtension(dict.Key), payload));
                            content.Add(imageContent, "image", dict.Key);

                            // Send the request and await the response
                            var response = client.PostAsync($"{sv[ATT_API_URL].Value}/forensics/detect", content).GetAwaiter().GetResult();

                            if (response.StatusCode == HttpStatusCode.Unauthorized)
                            {
                                if (count < maxRetries)
                                {
                                    count++;
                                    shouldRetry = true;
                                    Authenticate(taSessionId, taSdkUrl); // Call the method to authenticate and refresh tokens.
                                }
                                else
                                {
                                    throw new InvalidOperationException("Maximum retry attempts reached. Unable to authenticate.");
                                }
                            }

                            if (!response.IsSuccessStatusCode)
                            {
                                throw new WebException($"Error analyzing photo: {response.StatusCode}", WebExceptionStatus.ProtocolError);
                            }

                            return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        }
                    }
                }
                catch (WebException ex) when (ex.Status == WebExceptionStatus.ProtocolError && ex.Response is HttpWebResponse httpResponse)
                {
                    if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        if (count < maxRetries)
                        {
                            count++;
                            shouldRetry = true;
                            Authenticate(taSessionId, taSdkUrl); // Call the method to authenticate and refresh tokens.
                        }
                        else
                        {
                            throw new InvalidOperationException("Maximum retry attempts reached. Unable to authenticate.", ex);
                        }
                    }
                    else
                    {
                        throw new WebException($"HTTP Error: {httpResponse.StatusCode}", ex);
                    }
                }
                catch (WebException ex)
                {
                    string responseError = string.Empty;

                    if (ex.Response is HttpWebResponse errorResponse)
                    {
                        using (var stream = errorResponse.GetResponseStream())
                        using (var reader = new StreamReader(stream))
                        {
                            responseError = reader.ReadToEnd();
                        }
                    }

                    throw new WebException($"An error occurred: {responseError}", ex);
                }


            } while (shouldRetry);

            return "";
        }

        /// <summary>
        /// Communicates with Attestiv API to call their "Analyze Image Bulk" method.
        /// </summary>
        /// <param name="taFolderId">TotalAgility Folder ID; this can only be an image files</param>
        /// <param name="taSessionId">TA SessionID.</param>
        /// <param name="taSdkUrl">TA SDK URL.</param>
        public string AnalyzeImageBulk(string taFolderId, string taSessionId, string taSdkUrl)
        {
            int maxRetries = 3;
            int count = 0;
            bool shouldRetry;
            string responseContent = "";

            List<string> vars = new List<string>() { ATT_ACCESS_TOKEN, ATT_API_URL };
            Dictionary<string, byte[]> files = new Dictionary<string, byte[]>();
            KeyValuePair<string, byte[]> tafile;

            do
            {
                shouldRetry = false;
                ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
                var sv = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, vars);

                string folder = GetKTAFolder(taFolderId, taSdkUrl, taSessionId);
                foreach (string doc in GetFirstColumn(folder))
                {
                    tafile = GetKTADocumentFile(doc, taSdkUrl, taSessionId);
                    files[tafile.Key] = tafile.Value;
                }

                try
                {
                    using (var client = new HttpClient())
                    {
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", sv[ATT_ACCESS_TOKEN].Value);

                        using (var content = new MultipartFormDataContent())
                        {
                            int index = 1;
                            foreach (var file in files)
                            {
                                if (file.Value == null || file.Value.Length == 0)
                                    throw new ArgumentException($"Image at index {index} is null or empty.");

                                var imageContent = new ByteArrayContent(file.Value);
                                imageContent.Headers.ContentType = MediaTypeHeaderValue.Parse(GetMimeType(GetFileExtension(file.Key), file.Value));
                                content.Add(imageContent, "image", file.Key);
                                index++;
                            }

                            // Send the request and await the response
                            var response = client.PostAsync($"{sv[ATT_API_URL].Value}/forensics/detect", content).GetAwaiter().GetResult();

                            if (response.StatusCode == HttpStatusCode.Unauthorized)
                            {
                                if (count < maxRetries)
                                {
                                    count++;
                                    shouldRetry = true;
                                    Authenticate(taSessionId, taSdkUrl); // Call the method to authenticate and refresh tokens.
                                }
                                else
                                {
                                    throw new InvalidOperationException("Maximum retry attempts reached. Unable to authenticate.");
                                }
                            }

                            if (!response.IsSuccessStatusCode)
                            {
                                throw new WebException($"Error analyzing photos: {response.StatusCode}", WebExceptionStatus.ProtocolError);
                            }

                            responseContent = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        }
                    }
                }
                catch (WebException ex) when (ex.Status == WebExceptionStatus.ProtocolError && ex.Response is HttpWebResponse httpResponse)
                {
                    if (httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        if (count < maxRetries)
                        {
                            count++;
                            shouldRetry = true;
                            Authenticate(taSessionId, taSdkUrl); // Call the method to authenticate and refresh tokens.
                        }
                        else
                        {
                            throw new InvalidOperationException("Maximum retry attempts reached. Unable to authenticate.", ex);
                        }
                    }
                    else
                    {
                        throw new WebException($"HTTP Error: {httpResponse.StatusCode}", ex);
                    }
                }
                catch (WebException ex)
                {
                    string errorMsg = string.Empty;

                    if (ex.Response is HttpWebResponse errorResponse)
                    {
                        using (var stream = errorResponse.GetResponseStream())
                        using (var reader = new StreamReader(stream))
                        {
                            errorMsg = reader.ReadToEnd();
                        }
                    }

                    throw new WebException($"An error occurred: {errorMsg}", ex);
                }


                return responseContent;

            } while (shouldRetry);

        }

        private string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private KeyValuePair<string,byte[]> GetKTADocumentFile(string docID, string ktaSDKUrl, string sessionID)
        {
            byte[] file = new byte[1];
            byte[] buffer = new byte[4096];
            //string fileType = "pdf";
            string status = "OK";

            try
            {
                //Setting the URi and calling the get document API
                string KTAGetDocument = ktaSDKUrl + "/CaptureDocumentService.svc/json/GetDocument";
                HttpClient httpClient = new HttpClient();
                var getRequestPayload = new
                {
                    sessionId = sessionID,
                    documentId = docID
                };

                var getRequestContent = new StringContent(JsonConvert.SerializeObject(getRequestPayload), Encoding.UTF8, "application/json");
                var getResponse = httpClient.PostAsync(KTAGetDocument, getRequestContent).GetAwaiter().GetResult();

                if (!getResponse.IsSuccessStatusCode)
                {
                    throw new Exception($"Error fetching server variable: {getResponse.ReasonPhrase}");
                }

                var getResponseContent = getResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                // Parse the JSON into a JArray
                var getResponseJson = JObject.Parse(getResponseContent);
                string filename = getResponseJson["d"]?["FileName"]?.ToString();

                //Setting the URi and calling the get document API
                var KTAGetDocumentFile = ktaSDKUrl + "/CaptureDocumentService.svc/json/GetDocumentFile2";
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(KTAGetDocumentFile);
                httpWebRequest.ContentType = "application/json";
                httpWebRequest.Method = "POST";

                // CONSTRUCT JSON Payload
                using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
                {
                    string json = "{\"sessionId\":\"" + sessionID + "\",\"reportingData\": {\"Station\": \"\", \"MarkCompleted\": false }, \"documentId\":\"" + docID + "\", \"documentFileOptions\": { \"FileType\": \"\", \"IncludeAnnotations\": 0 } }";
                    streamWriter.Write(json);
                    streamWriter.Flush();
                }

                HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                Stream receiveStream = httpWebResponse.GetResponseStream();
                Encoding encode = System.Text.Encoding.GetEncoding("utf-8");
                StreamReader readStream = new StreamReader(receiveStream, encode);
                int streamContentLength = unchecked((int)httpWebResponse.ContentLength);

                using (Stream responseStream = httpWebResponse.GetResponseStream())
                {
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
                }

                return new KeyValuePair<string, byte[]>(filename, file);
            }
            catch (Exception ex)
            {
                throw new Exception("Exception GetKTADocumentFile: " + ex.ToString(), ex);
            }
        }

        private string GetKTAFolder(string folderID, string ktaSDKUrl, string sessionID)
        {
            string result = "";

            try
            {

                //Setting the URi and calling the get document API
                var KTAGetDocumentFile = ktaSDKUrl + "/CaptureDocumentService.svc/json/GetFolderFieldValue";
                HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(KTAGetDocumentFile);
                httpWebRequest.ContentType = "application/json";
                httpWebRequest.Method = "POST";

                // CONSTRUCT JSON Payload
                using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
                {
                    //string json = "{\"sessionId\":\"" + sessionID + "\",\"reportingData\": {\"Station\": \"\", \"MarkCompleted\": false }, \"folderId\":\"" + folderID + "\"}";
                    string json = "{\"sessionId\":\"" + sessionID + "\",\"folderId\":\"" + folderID + "\",\"reportingData\": {\"Station\": \"\",\"MarkCompleted\": false},\"fieldIdentity\": {\"Id\": \"8A3DFE7947444402A4FB47BD0CA2ADD5\",\"Table Row\": 0,\"Table Column\": 0,\"Name\": \"\"}";
                    streamWriter.Write(json);
                    streamWriter.Flush();
                }

                HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                using (var sr = new StreamReader(httpWebResponse.GetResponseStream()))
                {
                    result = sr.ReadToEnd();
                }

                return result;
            }
            catch (Exception ex)
            {
                return result;
            }

        }

        private string[] GetFirstColumn(string jsonString)
        {
            JObject jsonObject = JObject.Parse(jsonString);
            JArray valueArray = (JArray)jsonObject["d"]["Value"];

            string[] firstColumn = new string[valueArray.Count];
            for (int i = 0; i < valueArray.Count; i++)
            {
                firstColumn[i] = valueArray[i][0].ToString();
            }

            return firstColumn;
        }

        public static string GetMimeType(string fileExtension, byte[] fileBytes)
        {
            // Attempt to get MIME type based on the file extension
            if (!fileExtension.StartsWith(".")) { fileExtension = "." + fileExtension; }
            string mimeType = "application/octet-stream"; // Default unknown type
            if (!string.IsNullOrWhiteSpace(fileExtension))
            {
                try
                {
                    mimeType = System.Web.MimeMapping.GetMimeMapping(fileExtension);
                }
                catch
                {
                    // Handle exceptions if the MimeMapping fails or is unavailable
                }

                // If a valid MIME type was retrieved from the extension, return it
                if (!string.IsNullOrWhiteSpace(mimeType) && !mimeType.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase))
                {
                    return mimeType;
                }
            }

            // If extension-based lookup failed, use byte-signature-based lookup
            if (fileBytes == null || fileBytes.Length < 4)
                return mimeType;  // Default unknown type

            // Define file signatures in byte arrays
            byte[] jpg = new byte[] { 0xFF, 0xD8 };
            byte[] png = new byte[] { 0x89, 0x50, 0x4E, 0x47 };
            byte[] gif = new byte[] { 0x47, 0x49, 0x46 };
            byte[] tiffI = new byte[] { 0x49, 0x49, 0x2A, 0x00 };
            byte[] tiffM = new byte[] { 0x4D, 0x4D, 0x00, 0x2A };
            byte[] pdf = new byte[] { 0x25, 0x50, 0x44, 0x46 };

            // Compare file signature with defined signatures
            if (fileBytes.Take(jpg.Length).SequenceEqual(jpg))
                return "image/jpeg";

            if (fileBytes.Take(png.Length).SequenceEqual(png))
                return "image/png";

            if (fileBytes.Take(gif.Length).SequenceEqual(gif))
                return "image/gif";

            if (fileBytes.Take(tiffI.Length).SequenceEqual(tiffI) || fileBytes.Take(tiffM.Length).SequenceEqual(tiffM))
                return "image/tiff";

            if (fileBytes.Take(pdf.Length).SequenceEqual(pdf))
                return "application/pdf";

            return mimeType;  // Return default type if none of the byte signatures match
        }

        private string GetFileExtension(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return string.Empty;

            int lastDotIndex = fileName.LastIndexOf('.');
            if (lastDotIndex == -1 || lastDotIndex == fileName.Length - 1)
                return string.Empty; // No extension or the file ends with a dot.

            return fileName.Substring(lastDotIndex + 1);
        }
    }
}
