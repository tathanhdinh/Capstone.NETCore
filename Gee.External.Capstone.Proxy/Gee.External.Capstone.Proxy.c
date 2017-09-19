#include "capstone.h"

#ifdef _WIN32
_declspec(dllexport)
#endif
cs_arm* CapstoneArmDetail(cs_detail *detail)
{
	return &detail->arm;
}

#ifdef _WIN32
_declspec(dllexport)
#endif
cs_arm64* CapstoneArm64Detail(cs_detail *detail)
{
	return &detail->arm64;
}

#ifdef _WIN32
_declspec(dllexport)
#endif
cs_x86* CapstoneX86Detail(cs_detail *detail)
{
	return &detail->x86;
}
