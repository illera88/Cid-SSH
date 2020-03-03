## Compilation
You can always use the prebuilt binaries at [Release](https://github.com/RedRangerz/Cid-SSH/releases) but if you want to compile you should follow the next instructions:

Compilation can be done the same way for Windows, Linux and OSX using vcpkg:

```
# Install dependencies with vcpkg (static)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install boost-beast boost-asio boost-system libssh[core,openssl] # add on Windows --triplet x64-windows-static

# Configure and compile project
cd Cid-SSH
cmake -S . -B build_ssh -G "Visual Studio 16 2019" -A x64 -DWITH_WEBSOCKETS=OFF -DCMAKE_TOOLCHAIN_FILE=[VCPKG_PATH]/scripts/buildsystems/vcpkg.cmake # add on windows -DVCPKG_TARGET_TRIPLET=x64-windows-static ..
cmake --build_ssh . --config Release
cmake -S . -B build_wss -G "Visual Studio 16 2019" -A x64 -DWITH_WEBSOCKETS=ON -DCMAKE_TOOLCHAIN_FILE=[VCPKG_PATH]/scripts/buildsystems/vcpkg.cmake # add on windows -DVCPKG_TARGET_TRIPLET=x64-windows-static ..
cmake --build_wss . --config Release
```

To compile in `Linux` it is recommended to use [Alpine](https://alpinelinux.org/) since it uses `musl` which make very easy to get a completelly statically linked binary that can be used in any `Linux` distribution. 
To make things even easier the script called `build.sh` can be used to automatically build in any Linux distribution that uses `apk` package manager (as Alpine does).
