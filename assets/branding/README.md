# LocalAuth branding

Approved direction: one home/fingerprint/L emblem in mint on deep navy.
Generated using the built-in image-generation tool; PNG and ICO density exports retain the generated artwork.

- readme-header.png: horizontal wordmark/emblem lockup, README display.
- icon-master.png: square navy-backed emblem only, APK and Windows EXE master.
- Android: adaptive launcher drawable plus density-specific PNG fallbacks.
- Windows: home-server/assets/localauth.ico contains 16/24/32/48/64/128/256 pixel frames; build.rs embeds its resource into the executable.

Header prompt: Preserve the approved home/fingerprint/L geometry and palette. Arrange emblem on the left and exact LocalAuth wordmark on the right, centered vertically in a wide 3:1 navy banner. Smooth flat vector-like treatment, roomy margins, no tagline or extra elements.

Icon prompt: Preserve the approved geometry, including the connected left wall and isolated short L foot. Remove the wordmark, center mint emblem on a square navy canvas with generous Android mask margins. Crisp rounded strokes, no extra elements, shadows or text.

Windows MSVC builds require the Windows SDK resource compiler. Set RC to its path when automatic detection is unavailable. Non-Windows builds skip the Windows resource; Windows GNU builds require windres.
