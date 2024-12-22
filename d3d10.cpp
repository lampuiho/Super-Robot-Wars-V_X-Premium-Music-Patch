#include <windows.h>
#include <processenv.h>
#include <psapi.h>
#include <memoryapi.h>
#include <immintrin.h>
#pragma pack(1)

#ifdef __GNUC__
#define ATTRIBUTE_NAKED __attribute__((naked))
#else
#define ATTRIBUTE_NAKED __declspec(naked)
#endif

HINSTANCE hLThis = 0;
HINSTANCE hL = 0;
FARPROC p[3] = {0};
const BYTE CODE[] = { 0xB0,0x01,0x88,0x01,0xEB,0x18,0x0F,0x1F,0x00 };
const BYTE AOB[] = { 0x48,0x83,0xEC,0x30,0x48,0x8B,0xF9,0x48,0x8D,0x0D,0,0,0,0,0xE8,0,0,0,0,0x3C,0x01 };
const UINT32 BitMasks[] = { ~(UINT32)0b110000100001111111111 };
// this function converts 8bits to 8bytes... slowly...
UINT64 getMask(const UINT32* masks, size_t bitPos){
	BYTE out[8];
	
	//hope gcc magic makes this good
	UINT64 idxOuter = bitPos / 32;
	UINT32 mask = ~masks[idxOuter];
	BYTE bMask = (mask >> (bitPos % 32)) & 0xFF;
	for (UINT32 i = 0; i < 8; ++i){
		out[i] = (bMask & 1)*0xFF;
		bMask = bMask >> 1;
	}
	return *(UINT64*)out;
}
//assumed we don't run to the end of the region...
UINT64 __fastcall aobScanRegionSlow(const BYTE* aob, size_t len, const UINT32* masks, const BYTE* start, size_t sizeOfRegion){
	auto end = start + sizeOfRegion - len;
	auto aobEnd = aob+len;
	
	auto mIter = start;
	UINT64 vAob = *(UINT64*)aob;
	UINT64 mask = getMask(masks,0);
	while (mIter < end){
		UINT64 vDat = *(UINT64*)mIter;
		
		if ((vDat & mask) == vAob){
			auto mIterInner = mIter + 8;
			auto aobIter = aob + 8;
			size_t maskIter = 8;
			
			while (aobIter < aobEnd){
				vAob = *(UINT64*)aobIter;
				mask = getMask(masks,maskIter);
				vDat = *(UINT64*)mIterInner;
				
				if ((vDat & mask) == vAob){
					mIterInner += 8;
					aobIter += 8;
					maskIter += 8;
				}
				else{
					vAob = *(UINT64*)aob;
					mask = getMask(masks,0);
					break;
				}
			}
			if (aobIter >= aobEnd) //found match for first set of bytes
				return (UINT64)mIter;
		}
		mIter++;
	}
	return 0;
}
// returns address of first aob found. 0 if not found.
UINT64 aobScanProcess(const BYTE* aob, size_t len, const UINT32* masks){
	MODULEINFO info;

	//get base of process memory region and its size
	HMODULE base = GetModuleHandle(NULL);
	bool foundInfo = GetModuleInformation(GetCurrentProcess(),base,&info,sizeof(info));
	if(foundInfo) return aobScanRegionSlow(aob, len, masks, (BYTE*)base, info.SizeOfImage);

	return 0;
}
__declspec(noinline) void hookDemoMode(){
	UINT64 demoModeAddr = aobScanProcess(AOB, sizeof(AOB), BitMasks); //searching for the demoMode
	
	if (demoModeAddr)
	{
		DWORD backup;
		DWORD flNewProtect = PAGE_EXECUTE_WRITECOPY;
		void*codePtr = (void*)(demoModeAddr+0xA);
		bool success = VirtualProtect(codePtr,sizeof(CODE)+4,flNewProtect,&backup);
		
		if (success) {
			int*offsetPtr = (int*)codePtr;
			//change the offset to load premium pointer to rcx
			*offsetPtr = *offsetPtr+0x2E4;
			//change the code to load 1 to [rcx] and then bypass demo mode initialisation
			memcpy((void*)(demoModeAddr+0xE),CODE,sizeof(CODE));
			VirtualProtect(codePtr,sizeof(CODE)+4,backup,&flNewProtect);
		}
	}
}
BOOL WINAPI DllMain(HINSTANCE hInst,DWORD reason,LPVOID){
	if (reason == DLL_PROCESS_ATTACH){
		char path[1000];
		if (!ExpandEnvironmentStrings("%windir%\\system32\\d3d10.dll",path,sizeof(path)))
			return false;
		hLThis = hInst;
		hL = LoadLibrary(path);
		if (!hL) return false;
		
		p[0] = GetProcAddress(hL,"D3D10CompileEffectFromMemory");
		p[1] = GetProcAddress(hL,"D3D10CompileShader");
		p[2] = GetProcAddress(hL,"D3D10CreateBlob");
		
		hookDemoMode();
	}
	if (reason == DLL_PROCESS_DETACH)
		FreeLibrary(hL);
	return 1;
}
extern "C" ATTRIBUTE_NAKED void __stdcall __E__0__(){
	__asm__ __volatile__("jmp *%%rax" : :"p" (*p));
	__builtin_unreachable();
}
extern "C" ATTRIBUTE_NAKED void __stdcall __E__1__(){
	__asm__ __volatile__("jmp *%%rax" : : "p" (p[1]));
	__builtin_unreachable();
}
extern "C" ATTRIBUTE_NAKED void __stdcall __E__2__(){
	__asm__ __volatile__("jmp *%%rax" : : "p" (p[2]));
	__builtin_unreachable();
}
