using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
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

			NetworkClient TestClient = new NetworkClient("127.0.0.1", 5000);

			Thread.Sleep(20);

			int ClientCount = NetworkServer.Clients.Count;

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(1, ClientCount);
		}

		[TestMethod]
		public async Task PingTest()
		{
			Message.Initialize();
			NetworkServer.Start(5000);

			NetworkClient TestClient = new NetworkClient("localhost", 5000);
			PingResponse Response = await TestClient.Send<PingResponse>(new PingRequest() { Time = DateTime.FromBinary(12) });
			PingResponse Response2 = await TestClient.Send<PingResponse>(new PingRequest() { Time = DateTime.FromBinary(13) });
			PingResponse Response3 = await TestClient.Send<PingResponse>(new PingRequest() { Time = DateTime.FromBinary(14) });

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(12, Response?.Time.ToBinary());
			Assert.AreEqual(13, Response2?.Time.ToBinary());
			Assert.AreEqual(14, Response3?.Time.ToBinary());
		}

		[TestMethod]
		public async Task EncryptionTest()
		{
			Message.Initialize();
			NetworkServer.Start(5000);

			NetworkClient TestClient = new NetworkClient("localhost", 5000);
			bool EncryptionEnabled = await TestClient.InitializeEncryption();
			bool EncryptionClientEnabled = TestClient.HasEncryptedConnection;

			PingResponse Response = await TestClient.Send<PingResponse>(new PingRequest() { Time = DateTime.FromBinary(12) }, false);

			NetworkServer.Stop();
			TestClient.Dispose();

			Assert.AreEqual(true, EncryptionEnabled);
			Assert.AreEqual(true, EncryptionClientEnabled);
			Assert.AreEqual(12, Response?.Time.ToBinary());
		}
	}
}
