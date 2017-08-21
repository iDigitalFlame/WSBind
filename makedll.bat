gcc -c -o %2.o %1 -lws2_32 -lpsapi -liphlpapi
gcc -o %2.dll -s -shared %2.o -lws2_32 -lpsapi -liphlpapi
@del /s %2.o