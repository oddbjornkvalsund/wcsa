all: wcsa.c
	set CL=/nologo /I..\Detours\include
	set LIB=%LIB%;..\Detours\lib.X64
	cl /DEF wcsa.def /LD wcsa.c