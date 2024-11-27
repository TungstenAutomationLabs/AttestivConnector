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
            string docID = @"8492ba07-f620-4a02-b3d5-b22c012b78dc";

            APIHelper aPIHelper = new APIHelper();
            //bool login = aPIHelper.Initialize(url, id, pswd, sessionID, sdk);

            string response = aPIHelper.AnalyzeImage(docID, sessionID, sdk);
        }
    }
}
