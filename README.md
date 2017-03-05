# PyKeyBox
A mini key/password manager written in python using the AES encryption
algorithm from PyCrypto -- the python cryptography toolkit.

It stores your secret data, encrypted with AES, as key contents and associates
them with key titles you gave to provide you maximum

- flexibility: you can put whatever you want, in whatever format, into key
               contents including not only password, but also license keys,
               security questions, secret URLs, etc.

- simplicity : easy operations to any of your keys: add/view/modify/delete/list


## It is mini
Only one python file with size less than 10k bytes, and less than 250
lines of code, excluding empty lines and comments.


## Simple
```
keybox help             : show this help message and exit
keybox list             : list all key titles
keybox add    <title>   : add a new key title and content
keybox view   <keyword> : view the content for the key title matching the given keywords
keybox mod    <keyword> : modify the content for the key title matching the given keywords
keybox del    <keyword> : delete an existing key title matching the given keywords and the key content
keybox import <file>    : import all key titles and contents from a text file
keybox export [file]    : export all key titles and contents to stdout or a file
keybox reset            : reset the master password
```


## Portable
Just take the python script file and the sqlite database file with you
anywhere you want.


## Yet secure enough
It is based on the well known AES encryption algorithm.

