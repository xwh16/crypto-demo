gcc -fexec-charset=gbk -finput-charset=utf-8 spn+\spn+.c spn+\analysis_AES.c -lgmp -lm -o analysis_AES.exe
pause
analysis_AES >> table.txt