# Oblivion 6
Anti Cheat MMO

## DLL lifecycle contract

The DLL does not start worker threads from `DllMain`. The injector/host must explicitly invoke the exported entry point after loading the DLL:

1. Load the DLL successfully.
2. Call the exported `Oblivion_Entry()` function outside the loader lock.
3. Before unloading the DLL, call the exported `Oblivion_Shutdown()` function from a host thread.
4. Wait for `Oblivion_Shutdown()` to return, then unload the DLL.

Do not call either lifecycle export from `DllMain`, from `DllMain`-triggered loader callbacks, or while holding the Windows loader lock. Do not unload the module without first completing `Oblivion_Shutdown()`. Calling shutdown more than once is safe; restarting after shutdown is not supported by this DLL instance.

`Oblivion_Shutdown()` requests cancellation, joins initialization, stops the process watcher and self-integrity worker, and finally destroys the network reporter. These operations intentionally happen outside `DllMain`.
