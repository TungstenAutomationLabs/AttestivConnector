﻿using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace tungstenlabs.integration.attestiv.tests
{
    [TestClass]
    public class APIHelperTests
    {
        [TestMethod]
        public void AnalyzeImageBulk()
        {
            string folder = @"5e97807d-d6fe-489b-8f60-b235013ee29b";
            string json = @"";

            APIHelper oAPI = new APIHelper();
            //string bulk = oAPI.AnalyzeImageBulk(folder, Constants.TOTALAGILITY_SESSION_ID, Constants.TOTALAGILITY_API_URL);
            var result = oAPI.ExtractResultTamperScore(json);
        }
    }
}