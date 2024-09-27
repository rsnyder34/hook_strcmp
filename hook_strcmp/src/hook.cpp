#include "hook.h"

void Edit_Memory(char* src, char* dst, const unsigned int len)
{
	DWORD tmp;
	//In order to edit the program's memory, we need access.
	//Windows likes storing the protection rights in a var.
	VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &tmp);
	memcpy(dst, src, len);
	//Reset memory protection
	VirtualProtect(dst, len, tmp, &tmp);

}

bool Hook32(char* src, char* dst, const unsigned int len, void** old_func)
{
	//Program uses a 32bit relative jmp which requires 5 bytes
	if (len < 5)
		return false;
	//Allocate a piece of memory where we can copy assembly instructions without corrupting memory
	char* proxy = (char*)VirtualAlloc(0, len + 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//Steals the bytes from the original memory location
	memcpy(proxy, src, len);
	//32bit relative jmp payload needs the jmp instruction 0xE9 and 4 bytes for the desired location
	char payload[5] = { 0xE9,0x00,0x00,0x00,0x00 };
	//Calculating address for the jmp instruction and placing in payload
	*(uintptr_t*)(&payload[1]) = src - proxy - 5;
	//After stealing the orginal bytes we want to jmp to that calculated address in the payload
	memcpy(proxy + len, payload, sizeof(payload));
	//Now we replace the relative address with address of our custom function relative to the hook
	*(uintptr_t*)(&payload[1]) = dst - src - 5; //5 is for the len of jmp instructions
	//This is where we force the program to jump to our custom function
	Edit_Memory(payload, src, sizeof(payload));
	//Now the old function value will be that of the proxy's. This lets our hook return to the proxy memory region.
	*(void**)old_func = proxy;
}