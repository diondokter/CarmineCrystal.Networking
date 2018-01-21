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

		private static DelegateMessageProcessingModule<PingRequest> PingProcessingModule = new DelegateMessageProcessingModule<PingRequest>((RunTarget, Sender) => Sender.Send(new PingResponse() { Time = RunTarget.Time }));

		private List<Response> ResponseBuffer = new List<Response>();
		private TcpClient Client;

		private NetworkStream _NetworkConnection;
		private CryptoStream _CryptoWriteConnection;
		private CryptoStream _CryptoReadConnection;
		private Stream WriteConnection
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

				if (_CryptoWriteConnection != null)
				{
					return _CryptoWriteConnection;
				}
				else
				{
					return _NetworkConnection;
				}
			}
		}
		private Stream ReadConnection
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

				if (_CryptoReadConnection != null)
				{
					return _CryptoReadConnection;
				}
				else
				{
					return _NetworkConnection;
				}
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
			Client = new TcpClient(AddressFamily.InterNetwork | AddressFamily.InterNetworkV6);
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

		public void Send(Message Value)
		{
			lock (Client)
			{
				if (!Client.Connected || WriteConnection == null)
				{
					throw new SocketException((int)SocketError.NotConnected);
				}

				try
				{
					Value.SerializeInto(WriteConnection);
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

		public async Task<T> Send<T>(Request Value, long WaitTime = 2000) where T:Response
		{
			Send(Value);

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

		public async Task InitializeEncryption()
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
				AesManaged Cryptor = new AesManaged();
				Cryptor.KeySize = AESKeySize;
				Cryptor.IV = RSAEncryption.DecryptValue(Response.EncryptedAESIV);
				Cryptor.Key = RSAEncryption.DecryptValue(Response.EncryptedAESKey);
				Cryptor.Mode = CipherMode.CBC;
				Cryptor.Padding = PaddingMode.PKCS7;

				_CryptoWriteConnection = new CryptoStream(_NetworkConnection, Cryptor.CreateEncryptor(), CryptoStreamMode.Write);
				_CryptoReadConnection = new CryptoStream(_NetworkConnection, Cryptor.CreateDecryptor(), CryptoStreamMode.Read);
			}
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

				if (ReadConnection == null || !Client.Connected)
				{
					throw new SocketException((int)SocketError.NotConnected);
				}

				if (!DataAvailable)
				{
					return null;
				}

				return Message.DeserializeFrom(ReadConnection);
			}
		}

		private bool Disposed = false;
		public void Dispose()
		{
			lock (Client)
			{
				_CryptoWriteConnection?.Dispose();
				_CryptoReadConnection?.Dispose();
				_NetworkConnection?.Dispose();

				Client?.Dispose();
				Disposed = true;
			}
		}
	}
}
