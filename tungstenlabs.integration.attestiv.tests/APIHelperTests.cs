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
            string json = @"[{""detect_objects_result"":{""objects"":[{""label"":""Floor"",""primary"":false,""confidence"":100.0},{""label"":""Flooring"",""primary"":false,""confidence"":100.0},{""label"":""Indoors"",""primary"":false,""confidence"":100.0},{""label"":""Interior Design"",""primary"":false,""confidence"":100.0},{""label"":""Wood"",""primary"":false,""confidence"":100.0},{""label"":""Hardwood"",""primary"":false,""confidence"":100.0},{""label"":""Stained Wood"",""primary"":false,""confidence"":91.06}],""_version"":""release-72""},""detect_tampering_result"":{""assessments"":[{""model"":""metadata"",""compromisedScore"":1,""details"":{}},{""model"":""provenance"",""compromisedScore"":1,""details"":{}},{""model"":""quality"",""compromisedScore"":2,""details"":{}},{""model"":""downloads"",""compromisedScore"":1,""details"":{}},{""model"":""pop"",""compromisedScore"":1,""details"":{}},{""model"":""integrity"",""compromisedScore"":1,""details"":{}}],""tamperScore"":31,""image"":""real-floorboards.JPG"",""analysisId"":""f8b44e420a6dc5438748de10176c02e2"",""_version"":""release-72"",""type"":""photo""},""status"":""complete"",""image"":""real-floorboards.JPG"",""_version"":""release-72""}]";

            APIHelper oAPI = new APIHelper();
            //string bulk = oAPI.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            var result = oAPI.ExtractResultTamperScore(json);
        }
    }
}