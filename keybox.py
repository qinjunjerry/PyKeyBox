#!/usr/bin/env python

"""A mini key/password manager written in python using the AES encryption algorithm."""

import os
import sys
import os.path
import random
import sqlite3
import hashlib
import getpass
import argparse
import Crypto.Cipher.AES

class KeyBox(object):
    MASTER_KEY_TITLE = "<MASTER>"

    def __init__(self, file):
        self.conn = sqlite3.connect(file)
        # Use 8-bit string instead of unicode string, in order to read/write international
        # characters like Chinese
        self.conn.text_factory = str
        # The following line would use unicode string
        # self.conn.text_factory = lambda x: unicode(x, 'utf-8', 'ignore')
        self.cursor = self.conn.cursor()
        self.cursor.execute('CREATE TABLE IF NOT EXISTS keys (title TEXT PRIMARY KEY, content BLOB)')
        self.conn.commit()

    def list(self):
        titles = []
        self.cursor.execute('SELECT title FROM keys ORDER BY title')
        for row in self.cursor:
            if row[0] != KeyBox.MASTER_KEY_TITLE:
                titles.append( row[0] )
        return titles

    def exists(self, title):
        self.cursor.execute("SELECT content FROM keys WHERE title=?", (title,) )
        return self.cursor.fetchone() != None

    def assertExist(self, title):
        if not self.exists(title):
            exitWithError("Error: '%s' not found, try to list all titles or change to another title" % title)

    def initOrVerifyMasterPassword(self):
        if not self.exists(KeyBox.MASTER_KEY_TITLE):
            password = inputPassword("Create a new master password: ")
            if password == inputPassword("Confirm the master password: "):
                # the AES key of the master password, to encrypt key content
                self.aesKey = hashlib.sha256(password).digest()
                # the hash of the AES key, stored in db for master password verification
                keyHash = hashlib.sha256(self.aesKey).hexdigest()
                self.cursor.execute("INSERT INTO keys VALUES (?,?)", (KeyBox.MASTER_KEY_TITLE, keyHash ) )
                self.conn.commit()
            else:
                exitWithError("Error: password not match, please retry")
        else:
            # get the stored key hash
            self.cursor.execute("SELECT content FROM keys WHERE title=?", (KeyBox.MASTER_KEY_TITLE,) )
            storedKeyHash = self.cursor.fetchone()[0]
            # input master password
            password = inputPassword("Master password: ")
            self.aesKey = hashlib.sha256(password).digest()
            # compare key hash
            if hashlib.sha256(self.aesKey).hexdigest() != storedKeyHash:
                exitWithError("Error: incorrect master password, please retry")

    def view(self, title):
        self.cursor.execute("SELECT content FROM keys WHERE title=?", (title,) )
        encrypted = self.cursor.fetchone()[0]
        return decrypt(encrypted, self.aesKey)

    def set(self, title, plain):
        # for better print effect
        if plain[-1] != "\n": plain += "\n"
        encrypted = encrypt(plain, self.aesKey)
        self.cursor.execute("INSERT OR REPLACE INTO keys VALUES (?,?)",
                            (title, sqlite3.Binary(encrypted) ) )
        self.conn.commit()

    def delete(self, title):
        plain = self.view(title)
        self.cursor.execute("delete FROM keys WHERE title=?", (title,) )
        self.conn.commit()
        return plain


def inputContent(title):
    sys.stdout.write("Input content of '%s', enter an empty line to finish:\n" % title)
    lines = []
    while True:
        line = raw_input()
        if line:
            lines.append(line)
        else:
            break
    return '\n'.join(lines)

def inputPassword(text):
    password = getpass.getpass(text)
    if password == "":
        exitWithError("Error: password not given")
    return password

def encrypt(plain, aesKey):
    iv = ''.join( chr(random.randint(0, 0xFF)) for i in range(Crypto.Cipher.AES.block_size) )
    cipher = Crypto.Cipher.AES.AESCipher(aesKey, Crypto.Cipher.AES.MODE_CFB, iv)
    return iv + cipher.encrypt(plain)

def decrypt(encrypted, aesKey):
    iv = encrypted[0:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.AESCipher(aesKey, Crypto.Cipher.AES.MODE_CFB, iv)
    return cipher.decrypt(encrypted[Crypto.Cipher.AES.block_size:])

def readKeys(aFile):
    """
    Supported text file format is as follows:

    key title1:
    key content line 11
    key content line 12
    ...

    key title2:
    key content line 21
    key content line 22
    ...

    """
    keys = []
    with open(aFile, 'r') as fd:
        title = ''
        contentLines = []
        for line in fd:
            line = line.strip()
            if line.endswith(":"):  # title line
                if title != '' and contentLines != []:
                    # remove the empty lines at the end
                    while len(contentLines) > 0 and contentLines[-1] == "\n":
                        contentLines = contentLines[:-1]
                    # add to keys for return
                    keys.append( (title, '\n'.join([aLine for aLine in contentLines])) )
                # set next key title, and clear content
                title = line[:-1]
                contentLines = []
            elif title != "":
                contentLines.append(line)
            else:
                sys.stderr.write("Warn: line '%s' ignored: title missing\n" % line)
    # process the last key
    if title != '' and contentLines != []:
        # remove the empty lines at the end
        while len(contentLines) > 0 and contentLines[-1] == "\n":
            contentLines = contentLines[:-1]
        # add to keys for return
        keys.append( (title, '\n'.join([aLine for aLine in contentLines])) )

    return keys

def exitWithError(errMsg, errCode=-1):
    sys.stderr.write(errMsg + "\n")
    sys.exit(errCode)

def main():

    # parse command line arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-d', '--database', default='%s/keybox.sdb' % os.environ["HOME"],
                        help='the sqlite database file to store keys. Default: %s/keybox.sdb' 
                        % os.environ["HOME"] )
    subparsers = parser.add_subparsers(title="subcommands", dest="action",
            metavar='help|list|view|add|mod|del|import|export')
    helpParser = subparsers.add_parser("help", help="show this help message and exit")
    subParser = subparsers.add_parser("list", help="list all key titles (this is default)")
    subParser = subparsers.add_parser("view", help="view the content for the given key title")
    subParser.add_argument("title", help="a key title")
    subParser = subparsers.add_parser("add", help="add a new key title and content")
    subParser.add_argument("title", help="a key title")
    subParser = subparsers.add_parser("mod", help="modify the content for the given key title")
    subParser.add_argument("title", help="a key title")
    subParser = subparsers.add_parser("del", help="delete an existing key title and content")
    subParser.add_argument("title", help="a key title")
    subParser = subparsers.add_parser("import", help="import all key titles and contents from a text file")
    subParser.add_argument("file", help="a text file containing key titles and contents to import")
    subParser = subparsers.add_parser("export", help="export all key titles and contents to stdout or a file")
    subParser.add_argument("file", nargs='?', help="a text file to export the key titles and contents")
    
    # 'list' if not subcommand is given
    if len(sys.argv) == 1: sys.argv.append('list')
    
    args = parser.parse_args()

    if args.action == 'help':
         parser.print_help()
         sys.exit(0)

    keybox = KeyBox(args.database)
    if args.action == 'list':
        titles = keybox.list()
        if len(titles) == 0:
            sys.stdout.write("No item found\n")
        else:
            for title in titles:
                print "- " + title
        sys.exit(0)

    # check errors before init or verify master password
    if args.action == 'add':
        if keybox.exists(args.title):
            exitWithError("Error: '%s' exists, try to view it or add with another title" % args.title)
    if args.action in ['view', 'mod', 'del']:
        keybox.assertExist(args.title)
    elif args.action == "import":
        if not os.path.exists(args.file):
            exitWithError("Error: file '%s' not found." % args.file)
    elif args.action == "export":
        fd = sys.stdout
        if args.file != None:
            if os.path.exists(args.file):
                exitWithError("Error: file exists, please choose a different file to export")
            else:
                fd = open(args.file, 'w')

    keybox.initOrVerifyMasterPassword()
    if args.action in ['view', 'mod', 'del']:
         sys.stdout.write( "---\n%s:\n%s---\n" % (args.title, keybox.view(args.title) ) )

    if args.action == 'add':
        plain = inputContent(args.title)
        keybox.set(args.title, plain)
    elif args.action == "view":
         sys.exit(0)
    elif args.action == "mod":
        plain = inputContent(args.title)
        keybox.set(args.title, plain)
    elif args.action == "del":
        confirm = raw_input("Confirm to delete key '%s' [yes/no]? " % args.title)
        while confirm not in ['yes', 'no']:
            confirm = raw_input("Confirm to delete key '%s' [yes/no]? " % args.title)
        if confirm == 'yes':
            keybox.delete(args.title)
            sys.stdout.write ("Deleted.\n")
    elif args.action == "import":
        for title, content in readKeys(args.file):
            if keybox.exists(title):
                sys.stdout.write ("skipped %s: exists in database\n" % title)
            else:
                keybox.set(title, content)
                sys.stdout.write ("imported %s\n" % title)
    elif args.action == "export":
        if fd == sys.stdout: fd.write("---\n")
        for title in keybox.list():
            fd.write("%s:\n" % title)
            fd.write("%s" % keybox.view(title) )
            if fd == sys.stdout:
                fd.write("---\n")
            else:
                fd.write("\n")
        if fd != sys.stdout:
            sys.stdout.write("Exported to file %s\n" % args.file)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\nUser aborted.\n" )

