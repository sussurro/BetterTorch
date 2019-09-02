#!/bin/bash
xbuild /p:Configuration=Release MysteryMachine.csproj
mv bin/Release/MysteryMachineAssembly.dll MysteryMachineAssembly-4.dll
xbuild /p:Configuration=Release /tv:3.5 /p:FrameworkPathOverride=/usr/lib/mono/xbuild-frameworks/.NETFramework/v3.5 MysteryMachine.csproj
mv bin/Release/MysteryMachineAssembly.dll MysteryMachineAssembly-35.dll

