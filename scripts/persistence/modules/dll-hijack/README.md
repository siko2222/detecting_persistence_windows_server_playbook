# DLL-Hijack
* Get the dll definition
  ```bash
  git clone https://github.com/tothi/dll-hijack-by-proxying
  cd dll-hijack-by-proxying
  python3 gen_def.py ../profapi_orig.dll > profapi.def
  ```
* Create a c file to make a new dll, use the template from (https://github.com/tothi/dll-hijack-by-proxying)
* Create the new dll with custom code, exporting the same functions
  ```bash
  x86_64-w64-mingw32-gcc -shared -o profapi.dll profapi.c profapi.def -s
  ```
