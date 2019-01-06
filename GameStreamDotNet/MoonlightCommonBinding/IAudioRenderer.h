#pragma once

namespace Moonlight
{
	namespace Xbox
	{
		namespace Binding
		{
			using namespace Platform;

			public interface class IAudioRenderer
			{
				int Initialize(int audioFormat);

				void Start();

				void Stop();

				void Cleanup();

				int HandleFrame(const Array<unsigned char>^ frameData);
			};
		}
	}
}