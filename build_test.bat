..\PortableApps\mingw64\bin\gcc -shared -o d3d10.dll d3d10.cpp -static -O3 -mavx2 -lpsapi d3d10.def -Wl,--image-base=0x180000000
