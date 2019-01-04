#pragma once

#include "Limelight.h"
#include "IVideoRenderer.h"

namespace Moonlight
{
	namespace Xbox
	{
		namespace Binding
		{
			public ref class MoonlightCommonInterop
			{
			public:
				int StartConnection(IVideoRenderer^ videoRenderer);

			private:
				int DrSetup(
					int videoFormat, 
					int width, 
					int height, 
					int redrawRate, 
					void* context, 
					int drFlags);

				void DrStart();

				void DrStop();

				void DrCleanup();

				int DrSubmitDecodeUnit(PDECODE_UNIT decodeUnit);

				IVideoRenderer^ _videoRenderer;
			};
		}
	}
}