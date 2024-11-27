using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using tungstenlabs.integration.attestiv;

namespace AttestivHelperTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            string url = @"https://api.attestiv.net/api/v1";
            string id = "rafael.castro@tungstenautomation.com";
            string pswd = "Esoes!23Monda";
            string sdk = @"https://ktacloudeco-dev.ktaprt.dev.kofaxcloud.com/Services/Sdk";
            string sessionID = @"D2A967C768C7854B91C210DF77F118A4";
            string docID = @"d4a5d35c-3681-476f-9380-b23501322f98";
            string folder = @"5e97807d-d6fe-489b-8f60-b235013ee29b";

            APIHelper aPIHelper = new APIHelper();
            //bool login = aPIHelper.Initialize(url, id, pswd, sessionID, sdk);

            //string response = aPIHelper.AnalyzeImage(docID, sessionID, sdk);

            string bulk = aPIHelper.AnalyzeImageBulk(folder, sessionID, sdk);
        }
    }
}
