using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CarmineCrystal.Networking.Tests
{
    [TestClass]
    public class NetworkTest
    {
		[TestMethod]
		public void ServerConnectionLocalhostTest()
		{
			NetworkServer.Start(5000);

			Thread.Sleep(20);

			NetworkClient TestClient = new NetworkClient("localhost", 5000);

			Thread.Sleep(20);

			int ClientCount = NetworkServer.Clients.Count;

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(1, ClientCount);
		}

		[TestMethod]
		public void ServerConnectionLoopbackTest()
		{
			NetworkServer.Start(5000);

			Thread.Sleep(20);

			NetworkClient TestClient = new NetworkClient("127.0.0.1", 5000);

			Thread.Sleep(20);

			int ClientCount = NetworkServer.Clients.Count;

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(1, ClientCount);
		}

		[TestMethod]
		public async Task Pingtest()
		{
			Message.Initialize();
			NetworkServer.Start(5000);

			Thread.Sleep(20);

			NetworkClient TestClient = new NetworkClient("localhost", 5000);

			Thread.Sleep(20);

			PingResponse Response = await TestClient.Send<PingResponse>(new PingRequest() { Time = DateTime.FromBinary(12) });

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(12, Response.Time.ToBinary());
		}
	}
}
