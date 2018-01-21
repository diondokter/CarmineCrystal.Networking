using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Text;

namespace CarmineCrystal.Networking
{
	[ProtoContract]
	internal class PingRequest : Request
	{
		[ProtoMember(1)]
		public DateTime Time;
	}

	[ProtoContract]
	internal class PingResponse : Response
	{
		[ProtoMember(1)]
		public DateTime Time;
	}
}
