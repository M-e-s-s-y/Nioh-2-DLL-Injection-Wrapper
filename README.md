A `version.dll` wrapper to auto-inject Messy6666 aka SinGul4ritY's "Remove Special Effect Max Constraints" script.<br>

Just place the compiled dll in the same location as `nioh2.exe`.

If it's working correctly it will create a `Wrapper.log` when the game runs with contents like this:
```
2021-07-13 21:56:07	Orig version.dll loaded.
2021-07-13 21:56:12	Remove Special Effect Max Constraints (target address): 0x00007FF7FC5AE69B
2021-07-13 21:56:12	Remove Special Effect Max Constraints (inject address): 0x00007FF7FB660450
2021-07-13 21:56:12	Remove Special Effect Max Constraints patched.
```

Required lib for compiling: https://github.com/Synthlight/Base-Dll-Proxy

(Made for v1.28.08 on Steam.)
