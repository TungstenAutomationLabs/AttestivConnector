using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace tungstenlabs.integration.attestiv.tests
{
    [TestClass]
    public class APIHelperTests
    {
        [TestMethod]
        public void AnalyzeImageBulk()
        {
            APIHelper oAPI = new APIHelper();
            string bulk = oAPI.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
        }

        [TestMethod]
        public void AnalyzeImage()
        {
            APIHelper oAPI = new APIHelper();
            json = oAPI.AnalyzeImage(taObj, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            var result = oAPI.ExtractResultTamperScore(json);
        }
    }
}