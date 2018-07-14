all: wcsc.c
	set CL=/nologo /I..\Detours\include
	set LIB=%LIB%;..\Detours\lib.X64
	cl /DEF wcsc.def /LD wcsc.c