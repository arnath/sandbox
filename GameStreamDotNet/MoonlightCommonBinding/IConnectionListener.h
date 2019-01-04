#pragma once

public namespace Moonlight.Xbox.Binding
{
	public interface class IConnectionListener
	{
		void StageStarting(int stage);

		void StageComplete(int stage);

		void StageFailed(int stage, long errorCode);

		void Started();

		void ConnectionTerminated(long errorCode);


	};
}