using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace tungstenlabs.integration.attestiv.tests
{
    [TestClass]
    public class APIHelperTests
    {
        //[TestMethod]
        //public void AnalyzeImageBulk()
        //{
        //    APIHelper oAPI = new APIHelper();
        //    string bulk = oAPI.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
        //}

        [TestMethod]
        public void AnalyzeImage()
        {
            APIHelper oAPI = new APIHelper();
            string json = oAPI.AnalyzeImage("14f19145-2795-4ccb-91d4-b46e01553200", Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            var result = oAPI.ExtractResultTamperScore(json);
        }
    }




    /// <summary>
    /// Integration tests for AttestivArgusConnector (V2 / Argus platform).
    ///
    /// Prerequisites:
    ///   1. The following TotalAgility server variables must be configured:
    ///        ATT-V2-BASE-URL      = https://argus.api-us.attestiv.cloud
    ///        ATT-V2-TOKEN-URL     = https://auth.dev.attestiv.cloud/realms/attestiv/protocol/openid-connect/token
    ///        ATT-V2-ACCESS-TOKEN  = (leave blank — populated by Initialize)
    ///        ATT-V2-MAX-RETRIES   = 15
    ///        ATT-V2-FLAGS         = MSDRW
    ///
    ///   2. Replace all TODO values below with real TotalAgility document/folder IDs
    ///      and valid Argus credentials before running.
    ///
    ///   3. Run Initialize() test first to mint and cache the OAuth token.
    ///      All other tests depend on the cached token.
    ///
    /// OPEN QUESTION FOR ATTESTIV:
    ///   Confirm the meaning of each letter in the flags string (e.g. "MSDRW")
    ///   and valid values for audio_analysis_mode before running audio tests.
    /// </summary>
    [TestClass]
    public class APIHelperV2Tests
    {
        private const string CLIENT_ID = "";
        private const string CLIENT_SECRET = "";

        private const string IMAGE_DOC_ID = "96a59774-2413-49d1-8774-b48d014fba44";
        private const string DOCUMENT_DOC_ID = "a20dde7a-e774-495c-a646-b4830147f321";
        private const string FOLDER_ID = "TODO_REPLACE_WITH_FOLDER_ID";
        private const string VIDEO_DOC_ID = "TODO_REPLACE_WITH_VIDEO_DOC_ID";
        private const string AUDIO_DOC_ID = "TODO_REPLACE_WITH_AUDIO_DOC_ID";
        private const string IMAGE_URL = "TODO_REPLACE_WITH_PUBLIC_IMAGE_URL";
        private const string DOCUMENT_URL = "TODO_REPLACE_WITH_PUBLIC_DOCUMENT_URL";
        private const string VIDEO_URL = "TODO_REPLACE_WITH_PUBLIC_VIDEO_URL";

        private const string PROXY_URL = "TODO_REPLACE_WITH_PROXY_URL";
        private const string PROXY_USERNAME = "TODO_REPLACE_WITH_PROXY_USERNAME";
        private const string PROXY_PASSWORD = "TODO_REPLACE_WITH_PROXY_PASSWORD";

        [TestMethod]
        public void AnalyzeImage()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeImage(
                IMAGE_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeImage1()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeImage1(
                IMAGE_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET,
                new DO_ArgusProxySettings
                {
                    Url = PROXY_URL,
                    Username = PROXY_USERNAME,
                    Password = PROXY_PASSWORD
                }
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeImageByUrl()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeImageByUrl(
                IMAGE_URL,
                "test-image-url-001",
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeImageBulk()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeImageBulk(
                FOLDER_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeDocument()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeDocument(
                DOCUMENT_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeDocument1()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeDocument1(
                DOCUMENT_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET,
                new DO_ArgusProxySettings
                {
                    Url = PROXY_URL,
                    Username = PROXY_USERNAME,
                    Password = PROXY_PASSWORD
                }
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeDocumentByUrl()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeDocumentByUrl(
                DOCUMENT_URL,
                "test-document-url-001",
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeVideo()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeVideo(
                VIDEO_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeVideoByUrl()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeVideoByUrl(
                VIDEO_URL,
                "test-video-url-001",
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void AnalyzeAudio()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string result = connector.AnalyzeAudio(
                AUDIO_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void ExtractResultScore()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string jobResult = connector.AnalyzeImage(
                IMAGE_DOC_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            string result = connector.ExtractResultScore(jobResult);
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }

        [TestMethod]
        public void ExtractBulkResultScore()
        {
            AttestivArgusConnector connector = new AttestivArgusConnector();
            string bulkResult = connector.AnalyzeImageBulk(
                FOLDER_ID,
                Constants.TOTALAGILITY_SESSION_ID,
                Constants.TOTALAGILITY_API_URL,
                CLIENT_ID,
                CLIENT_SECRET
            );
            string result = connector.ExtractBulkResultScore(bulkResult, maxTamperScore: 50);
            Assert.IsFalse(string.IsNullOrEmpty(result));
        }
    }





}