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

            APIHelper aPIHelper = new APIHelper();
            bool login = aPIHelper.Initialize(url, id, pswd, sessionID, sdk);
        }
    }
}
