#pragma once

public namespace Moonlight.Xbox.Binding
{
	using namespace Platform;

	public interface class IAudioRendererCallbacks
	{
		int Initialize(int audioFormat);

		void Start();

		void Stop();

		void Cleanup();

		int HandleFrame(Array<byte>^ frameData);
	};
}