#include <stdlib.h>
#include <string>
#include "Limelight.h"
#include "MoonlightCommonInterop.h"
#include "IVideoRenderer.h"

using namespace Platform;
using namespace Moonlight::Xbox::Binding;

#define INITIAL_FRAME_BUFFER_SIZE 1048576
static int g_VideoFrameBufferSize = 0;
static char* g_VideoFrameBuffer;

int MoonlightCommonInterop::DrSetup(
	int videoFormat, 
	int width, 
	int height, 
	int redrawRate, 
	void* context, 
	int drFlags)
{
	if (_videoRenderer == nullptr)
	{
		return -1;
	}

	return _videoRenderer->Initialize(videoFormat, width, height, redrawRate);
}

void MoonlightCommonInterop::DrStart()
{
	if (_videoRenderer != nullptr)
	{
		_videoRenderer->Start();
	}
}

void MoonlightCommonInterop::DrStop()
{
	if (_videoRenderer != nullptr)
	{
		_videoRenderer->Stop();
	}
}

void MoonlightCommonInterop::DrCleanup()
{
	if (_videoRenderer != nullptr)
	{
		_videoRenderer->Cleanup();
	}
}

int MoonlightCommonInterop::DrSubmitDecodeUnit(PDECODE_UNIT decodeUnit)
{
	if (_videoRenderer == nullptr)
	{
		return DR_NEED_IDR;
	}

	// Resize the frame buffer if the current frame is too big.
	// This is safe without locking because this function is
	// called only from a single thread.
	if (g_VideoFrameBufferSize < decodeUnit->fullLength) 
	{
		g_VideoFrameBufferSize = decodeUnit->fullLength;
		g_VideoFrameBuffer = (char*)malloc(g_VideoFrameBufferSize);
	}

	if (g_VideoFrameBuffer == NULL) 
	{
		g_VideoFrameBufferSize = 0;
		return DR_NEED_IDR;
	}

	PLENTRY currentEntry = decodeUnit->bufferList;
	int offset = 0;
	while (currentEntry != NULL)
	{
		// Submit parameter set NALUs separately from picture data
		if (currentEntry->bufferType != BUFFER_TYPE_PICDATA) 
		{
			// Use the beginning of the buffer each time since this is a separate
			// invocation of the decoder each time.
			memcpy(&g_VideoFrameBuffer[0], currentEntry->data, currentEntry->length);

			int ret = 
				_videoRenderer->HandleFrame(
					ArrayReference<unsigned char>((unsigned char*)g_VideoFrameBuffer, currentEntry->length),
					currentEntry->bufferType,
					decodeUnit->frameNumber,
					decodeUnit->receiveTimeMs);
			if (ret != DR_OK)
			{
				return ret;
			}
		}
		else
		{
			memcpy(&g_VideoFrameBuffer[offset], currentEntry->data, currentEntry->length);
			offset += currentEntry->length;
			currentEntry = currentEntry->next;
		}
	}

	return
		_videoRenderer->HandleFrame(
			ArrayReference<unsigned char>((unsigned char*)g_VideoFrameBuffer, offset),
			BUFFER_TYPE_PICDATA,
			decodeUnit->frameNumber,
			decodeUnit->receiveTimeMs);
}

int MoonlightCommonInterop::StartConnection(IVideoRenderer^ videoRenderer)
{
	_videoRenderer = videoRenderer;
}