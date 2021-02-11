#ifndef ASMHOOK_H
#define ASMHOOK_H
#ifdef __cplusplus
extern "C" { 
#endif
	void __cdecl InstallHook(void*, void* pDetour, size_t size, void** trampoline);
#ifdef __cplusplus
}
#endif
#endif
