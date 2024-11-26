using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
        public bool Initialize(string baseApiUrl, string userId, string pswd, string taSessionId, string taSdkUrl)
        {
            // Encode the password using SHA-256
            string hashedPassword = ComputeSha256Hash(pswd);

            string tokenUrl = $"{baseApiUrl}/users/login";

            string json = $"{{ \"username\": \"{userId}\", \"password\": \"{hashedPassword}\" }}"; 

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
            dict[ATT_PSWD_ID] = new KeyValuePair<string, string>(dict[ATT_PSWD_ID].Key, hashedPassword);

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

            return Initialize(sv[ATT_API_URL].Value, sv[ATT_USER_ID].Value, sv[ATT_PSWD_ID].Value, taSessionId, taSdkUrl);
        }

        /// <summary>
        /// Communicates with Attestiv API to call their "Analyze Image" method.
        /// </summary>
        /// <param name="taDocId">TotalAgility Document ID.</param>
        /// <param name="taSessionId">TA SessionID.</param>
        /// <param name="taSdkUrl">TA SDK URL.</param>
        public string AnalyzeImage(string taDocId, string taSessionId, string taSdkUrl, string docFileExt)
        {
            int maxRetries = 3;
            int count = 0;
            bool shouldRetry;
            string responseContent = "";

            List<string> vars = new List<string>() { ATT_ACCESS_TOKEN, ATT_API_URL };

            do
            {
                shouldRetry = false;
                ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
                var sv = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, vars);

                string eventUrl = $"{sv[ATT_API_URL].Value}/forensics/detect";
                byte[] payload = GetKTADocumentFile(taDocId, taSdkUrl, taSessionId);

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(eventUrl);
                request.Method = "POST";
                request.ContentType = GetMimeType(docFileExt, payload);
                request.ContentLength = payload.Length;
                request.Headers["Authorization"] = $"Bearer {sv[ATT_ACCESS_TOKEN].Value}";
                request.Accept = "application/json";

                using (Stream writer = request.GetRequestStream())
                {
                    writer.Write(payload, 0, payload.Length);
                    writer.Flush();
                }

                try
                {
                    using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                    {
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            responseContent = reader.ReadToEnd();
                        }
                    }
                }
                catch (WebException ex) when (ex.Response is HttpWebResponse httpResponse && httpResponse.StatusCode == HttpStatusCode.Unauthorized)
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
                catch (WebException ex)
                {
                    using (HttpWebResponse response = (HttpWebResponse)ex.Response)
                    {
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            responseContent = reader.ReadToEnd();
                        }
                    }
                }

            } while (shouldRetry);

            return responseContent;
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

        private byte[] GetKTADocumentFile(string docID, string ktaSDKUrl, string sessionID)
        {
            byte[] result = new byte[1];
            byte[] buffer = new byte[4096];
            //string fileType = "pdf";
            string status = "OK";

            try
            {
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

                        result = memoryStream.ToArray();
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                status = "An error occured: " + ex.ToString();
                return result;
            }
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
    }
}
