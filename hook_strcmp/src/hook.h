#pragma once
#include <Windows.h>

void Edit_Memory(char* src, char* dst, const unsigned int len);

bool Hook32(char* src, char* dst, const unsigned int len, void** old_func);