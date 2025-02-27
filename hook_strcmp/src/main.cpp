#include <iostream>
#include "hook.h"
#define print(...) std::cout << "[*] " << __VA_ARGS__ << "\n"
#define error(...) std::cout << "[!] " << __VA_ARGS__ << "\n"

//Creates a blueprint for the strcmp function we are hooking
typedef int(__stdcall* t_lstrcmpA)(const char* str1, const char* str2);
//This will be used for the return value of the hook function
t_lstrcmpA old_lstrcmpA = nullptr;


//Hook function has to have same return type and parameters so bytes are not misplaced
int __stdcall hook(const char* str1, const char* str2)
{
	//This will display our string as well as the password
	print("strcmp( " << str1 << ", " << str2 << " )");

	//This will return to the proxy memory region where the stolen bytes are executed
	//and will jmp back to the location after the hook. That way nothing crashes.
	return old_lstrcmpA(str1, str2);
}

int __stdcall MainThread(HMODULE hMod)
{
	//Console for debugging
	FILE* f;
	AllocConsole();
	freopen_s(&f, "CONOUT$", "w", stdout);
	print("Hello");
	//When putting the crackme into x32dbg, we see that the lstrcmpA (strcmp)
	//originates in  the kernel32 library file. So we need its address.

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
	{
		error("Failed to get handle to target module");
		return 1;
	}
	//Finds the location of function call in memory
	void* lstrcmpA_address = GetProcAddress(hKernel32, "lstrcmpA");
	if (!lstrcmpA_address)
	{
		error("Failed to get the memory location of strcmp");
		return 2;
	}
	else
		print("strcmp address is " << lstrcmpA_address);
	char old_bytes[5] = { 0 };
	//used for storing the original bytes so we can patch the program
	//when we see the password
	memcpy(old_bytes, (char*)lstrcmpA_address, sizeof(old_bytes));
	//The len is 5 because in x32dbg the function location has a
	//a sequence of 5 bytes with nothing overlapping into another row
	//				8BFF	mov edi, edi
	//				55		push ebp
	//				8BEC	mov ebp, esp
	//so if there were more bytes after EC I would have to include them,
	//however, the third line ends the sequence of 5 bytes (Lucky)
	if (!Hook32((char*)lstrcmpA_address, (char*)hook, 5, (void**)&old_lstrcmpA))
	{
		error("Hook function failed to execute in the main thread");
		return 3;
	}
	else
		print("Hook is in place");

	//This loop will keep the hook in place. After everything is returned to normal
	//so program does not crash. 
	while (!GetAsyncKeyState(VK_END)) {}

	Sleep(4000);
	fclose(f);
	FreeConsole();
	//After seeing the password, we can return everything back to normal to solve the problem.
	Edit_Memory(old_bytes, (char*)lstrcmpA_address, sizeof(old_bytes));

	FreeLibraryAndExitThread(hMod, 0);
	return 0;

}


bool __stdcall DllMain(HMODULE hMod, DWORD reason, void* lpr)
{
	if (reason == 1)
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hMod, 0, 0);

	return true;
}
