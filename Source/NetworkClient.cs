using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CarmineCrystal.Networking
{
	public class NetworkClient : IDisposable
	{
		public IPAddress ConnectedIP => ((IPEndPoint)Client?.Client.RemoteEndPoint).Address;
		public bool IsConnected => Client.Connected;
		public bool DataAvailable => _NetworkConnection?.DataAvailable ?? false;
		public bool HasEncryptedConnection => Cryptor != null;

		private static readonly DelegateMessageProcessingModule<PingRequest> PingProcessingModule = new DelegateMessageProcessingModule<PingRequest>((RunTarget, Sender) => Sender.Send(new PingResponse() { Time = RunTarget.Time, ID = RunTarget.ID }));
		private static readonly DelegateMessageProcessingModule<KeyExchangeRequest> KeyExchangeProcessingModule = new DelegateMessageProcessingModule<KeyExchangeRequest>((RunTarget, Sender) => Sender.ProcessKeyExchange(RunTarget));

		private List<Response> ResponseBuffer = new List<Response>();
		private TcpClient Client;
		private AesManaged Cryptor;

		private NetworkStream _NetworkConnection;
		private Stream Connection
		{
			get
			{
				if (Disposed)
				{
					return null;
				}

				if (_NetworkConnection == null)
				{
					try
					{
						_NetworkConnection = Client?.GetStream();
					}
					catch (InvalidOperationException)
					{
						Dispose();
						return null;
					}
				}

				return _NetworkConnection;
			}
		}

		private MessageProcessingModule[] ProcessingModules;

		public NetworkClient(TcpClient Client, params MessageProcessingModule[] ProcessingModules)
		{
			this.Client = Client;
			this.ProcessingModules = ProcessingModules;

			new Task(LoopReceive).Start();
		}

		public NetworkClient(string Host, int Port, params MessageProcessingModule[] ProcessingModules)
		{
			Client = new TcpClient(AddressFamily.InterNetworkV6);
			this.ProcessingModules = ProcessingModules;

			Connect(Host, Port);		
		}

		private void Connect(string Host, int Port)
		{
			try
			{
				Client.ConnectAsync(Host, Port).Wait();
			}
			catch
			{
				throw;
			}

			new Task(LoopReceive).Start();
		}

		public void SendEncrypted(Message Value)
		{
			Send(Value, true);
		}

		public void Send(Message Value)
		{
			Send(Value, HasEncryptedConnection);
		}

		public void Send(Message Value, bool Encrypted)
		{
			lock (Client)
			{
				if (!Client.Connected || Connection == null)
				{
					throw new SocketException((int)SocketError.NotConnected);
				}

				try
				{
					if (Encrypted)
					{
						if (Cryptor == null)
						{
							throw new CryptographicUnexpectedOperationException("Encryption is not initialized...");
						}

						EncryptedMessage EncryptedValue = new EncryptedMessage();
						EncryptedValue.SetPayload(Value, Cryptor);
						Value = EncryptedValue;
					}

					Value.SerializeInto(Connection);
				}
				catch (IOException)
				{
					if (NetworkServer.Started)
					{
						NetworkServer.RemoveClient(this, NetworkServer.ClientRemoveReason.Disconnect);
					}
				}
			}
		}

		public async Task<T> SendEncrypted<T>(Request Value, long WaitTime = 2000) where T : Response
		{
			return await Send<T>(Value, true, WaitTime);
		}

		public async Task<T> Send<T>(Request Value, long WaitTime = 2000) where T : Response
		{
			return await Send<T>(Value, HasEncryptedConnection, WaitTime);
		}

		public async Task<T> Send<T>(Request Value, bool Encrypted, long WaitTime = 2000) where T : Response
		{
			Send(Value, Encrypted);

			T Response = null;
			Stopwatch Watch = Stopwatch.StartNew();

			while (Response == null && Watch.ElapsedMilliseconds < WaitTime && !Disposed)
			{
				lock (ResponseBuffer)
				{
					Response = ResponseBuffer.OfType<T>().FirstOrDefault(x => x.ID == Value.ID);
					if (Response != null)
					{
						ResponseBuffer.Remove(Response);
						return Response;
					}
				}

				await Task.Delay(5);
			}

			return Response;
		}

		public async Task<bool> InitializeEncryption()
		{
			int RSAKeySize = 4096;
			int AESKeySize = 256;

			RSA RSAEncryption = RSA.Create();
			RSAEncryption.KeySize = RSAKeySize;

			RSAParameters PublicParameters = RSAEncryption.ExportParameters(false);

			KeyExchangeRequest Request = new KeyExchangeRequest() { RSAKeySize = RSAKeySize, AESKeySize = AESKeySize, RSAExponent = PublicParameters.Exponent, RSAModulus = PublicParameters.Modulus };
			KeyExchangeResponse Response = await Send<KeyExchangeResponse>(Request);

			if (Response?.Accepted ?? false)
			{
				Cryptor = new AesManaged();
				Cryptor.KeySize = AESKeySize;
				Cryptor.IV = RSAEncryption.Decrypt(Response.EncryptedAESIV, RSAEncryptionPadding.Pkcs1);
				Cryptor.Key = RSAEncryption.Decrypt(Response.EncryptedAESKey, RSAEncryptionPadding.Pkcs1);
				Cryptor.Mode = CipherMode.CBC;
				Cryptor.Padding = PaddingMode.PKCS7;

				return true;
			}

			return false;
		}

		private void ProcessKeyExchange(KeyExchangeRequest Request)
		{
			RSA RSAEncryption = RSA.Create();
			RSAEncryption.KeySize = Request.RSAKeySize;

			RSAParameters PublicParameters = new RSAParameters() { Exponent = Request.RSAExponent, Modulus = Request.RSAModulus };
			RSAEncryption.ImportParameters(PublicParameters);

			Cryptor = new AesManaged();
			Cryptor.KeySize = Request.AESKeySize;
			Cryptor.GenerateIV();
			Cryptor.GenerateKey();
			Cryptor.Mode = CipherMode.CBC;
			Cryptor.Padding = PaddingMode.PKCS7;

			KeyExchangeResponse Response = new KeyExchangeResponse() { Accepted = true, EncryptedAESIV = RSAEncryption.Encrypt(Cryptor.IV, RSAEncryptionPadding.Pkcs1), EncryptedAESKey = RSAEncryption.Encrypt(Cryptor.Key, RSAEncryptionPadding.Pkcs1), ID = Request.ID };
			Send(Response);
		}

		private async void LoopReceive()
		{
			while (!Disposed)
			{
				Message ReceivedMessage = Receive();

				if (ReceivedMessage == null)
				{
					await Task.Delay(5);
					continue;
				}

				if (ReceivedMessage is EncryptedMessage ReceivedEncryptedMessage)
				{
					if (Cryptor == null)
					{
						continue;
					}

					ReceivedMessage = ReceivedEncryptedMessage.GetPayload(Cryptor);
				}

				if (ReceivedMessage is Response)
				{
					lock (ResponseBuffer)
					{
						ResponseBuffer.Add((Response)ReceivedMessage);
					}
				}
				else
				{
					new Task(() =>
					{
						KeyExchangeProcessingModule.Process(ReceivedMessage, this);
						PingProcessingModule.Process(ReceivedMessage, this);
						for (int i = 0; i < ProcessingModules.Length; i++)
						{
							ProcessingModules[i].Process(ReceivedMessage, this);
						}
					}).Start();
				}
			}
		}

		private Message Receive()
		{
			lock (Client)
			{
				if (Disposed)
				{
					return null;
				}

				if (Connection == null || !Client.Connected)
				{
					throw new SocketException((int)SocketError.NotConnected);
				}

				if (!DataAvailable)
				{
					return null;
				}

				return Message.DeserializeFrom(Connection);
			}
		}

		private bool Disposed = false;
		public void Dispose()
		{
			lock (Client)
			{
				Client.Dispose();
				Disposed = true;
			}
		}
	}
}
