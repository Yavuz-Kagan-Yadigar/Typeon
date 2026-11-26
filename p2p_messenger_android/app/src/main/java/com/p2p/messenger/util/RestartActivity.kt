package com.p2p.messenger.util

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process

/**
 * Runs in its own `:restart` process (see AndroidManifest). It kills the app process, then starts the app again.
 * A process cannot do this for itself: the screen it starts just before `exit` lands in the dying process.
 */
class RestartActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val oldPid = intent.getIntExtra(EXTRA_PID, -1)
        if (oldPid > 0) Process.killProcess(oldPid)
        packageManager.getLaunchIntentForPackage(packageName)?.component?.let {
            startActivity(Intent.makeRestartActivityTask(it))
        }
        finish()
        Runtime.getRuntime().exit(0)
    }

    companion object {
        const val EXTRA_PID = "old_pid"
        const val PROCESS_SUFFIX = ":restart"
    }
}
