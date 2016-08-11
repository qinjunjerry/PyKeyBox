# PyKeyBox
A mini key/password manager written in python using the AES encryption algorithm.

## It is mini
Only one python file with size less than 10k bytes, and less than 200 
lines of code, excluding empty lines and comments.

## simple
keybox help         : show this help message and exit
keybox list         : list all key names
keybox view   <name>: view the content for the given key name
keybox add    <name>: add a new key name and content
keybox mod    <name>: modify the content for the given key name
keybox del    <name>: delete an existing key name and content
keybox import <file>: import all key names and contents from a text file
keybox export [file]: export all key names and contents to stdout or a file

## portable
Just take the python file and the db file with you anywhere you want.

## yes secure enough
It is based on the well known AES encryption algorithm.
