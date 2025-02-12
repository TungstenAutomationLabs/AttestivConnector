using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace tungstenlabs.integration.attestiv.tests
{
    [TestClass]
    public class APIHelperTests
    {
        [TestMethod]
        public void AnalyzeImageBulk()
        {
            string taObj = @"";
            string json = @"";

            APIHelper oAPI = new APIHelper();
            //string bulk = oAPI.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            json = oAPI.AnalyzeImage(taObj, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            var result = oAPI.ExtractResultTamperScore(json);
        }
    }
}