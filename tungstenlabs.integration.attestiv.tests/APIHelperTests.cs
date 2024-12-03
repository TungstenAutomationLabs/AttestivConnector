using Microsoft.VisualStudio.TestTools.UnitTesting;
using tungstenlabs.integration.attestiv;

namespace tungstenlabs.integration.attestiv.tests
{
    [TestClass]
    public class APIHelperTests
    {
        [TestMethod]
        public void AnalyzeImageBulk()
        {
            string folder = @"5e97807d-d6fe-489b-8f60-b235013ee29b";

            APIHelper aPIHelper = new APIHelper();
            string bulk = aPIHelper.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
        }
    }
}