msvc:
		cl /nologo /O2 /Ot /DTEST test.c kuznyechik.c
gnu:
		gcc -DTEST -Wall -O2 test.c kuznyechik.c -otest	 
clang:
		clang -DTEST -Wall -O2 test.c kuznyechik.c -otest	    