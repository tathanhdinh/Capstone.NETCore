#include "capstone.h"

_declspec(dllexport) cs_arm* ArmDetail(cs_detail *detail)
{
	return &detail->arm;
}

_declspec(dllexport) cs_arm64* Arm64Detail(cs_detail *detail)
{
	return &detail->arm64;
}

_declspec(dllexport) cs_x86* X86Detail(cs_detail *detail)
{
	return &detail->x86;
}