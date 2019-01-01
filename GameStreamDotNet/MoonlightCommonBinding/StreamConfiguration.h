#pragma once

namespace Moonlight.Xbox.Binding
{
	public enum class StreamLocation { Local, Remote, Auto };

	public enum class AudioConfiguration { Stereo, 5Point1Surround };

	public ref class StreamConfiguration
	{
	public:

		// Width in pixels
		property int Width;

		// Height in pixels
		property int Height;

		property int Fps;

		property int Bitrate;

		// Max video packet size in bytes (use 1024 if unsure). If Location is set
		// to Auto (see below) and determines the stream is remote, it will cap 
		// this value at 1024 to avoid MTU-related issues like packet loss and 
		// fragmentation.
		property int MaxPacketSize;

		// Determines whether to enable remote (over the Internet)
		// streaming optimizations. Auto uses a heuristic (whether the target
		// address is in the RFC 1918 address blocks) to decide whether the
		// stream is remote or not.
		property StreamLocation Location;

		// Specifies the channel configuration of the audio stream.
		property AudioConfiguration AudioConfiguration;

		// Indicates whether the client can accept an H.265 video stream
		// if the server is able to provide one.
		property bool SupportsHevc;

		// Specifies that the client is requesting an HDR H.265 video stream.
		// This should only be set if:
		// 1) The client decoder supports HEVC Main10 profile (SupportsHevc must be true)
		// 2) The server has support for HDR as indicated by ServerCodecModeSupport in /serverinfo
		// 3) The app supports HDR as indicated by IsHdrSupported in /applist
		property bool EnableHdr;

		// Specifies the percentage that the specified bitrate will be adjusted
		// when an HEVC stream will be delivered. This allows clients to opt to
		// reduce bandwidth when HEVC is chosen as the video codec rather than
		// (or in addition to) improving image quality.
		property int HevcBitratePercentageMultiplier;

		// If specified, the client's display refresh rate x 100. For example, 
		// 59.94 Hz would be specified as 5994. This is used by recent versions
		// of GFE for enhanced frame pacing.
		property int ClientRefreshRateX100;

		// AES encryption data for the remote input stream. This must be
		// the same as what was passed as rikey and rikeyid in /launch 
		// and /resume requests.
		property Array<byte>^ RemoteInputAesKey;

		property Array<byte>^ RemoteInputAesIv;
	};
}