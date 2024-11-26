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
    }
}
