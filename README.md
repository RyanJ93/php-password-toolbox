# Password toolkit (PHP edition)

Password toolkit is a simple library that will help you handling passwords with PHP without any dependencies.
This library is a PHP porting from the "Password toolkit" library available for Node.js.
You can use this library to generate suggested passwords, analyse user provided passwords in order to get a strength score and create a hash that can be stored within the database.
Note that this library require PHP version 7.0 or greater.

# Password analysis

First, you need to create an instance of the "Analyzer" class as following:

`$analyzer = new PHPPasswordToolBox\Analyzer();`

Simple analysis:

`$analyzer->analyze($password);`

Complete analysis:

`$analyzer->setDictionaryPath('rockyou.txt')->completeAnalysis($password);`

Note that the complete analysis require a dictionary containing a list of weak passwords, passwords in this list must be separated by a break line (\n).
You can download dictionaries [here](https://wiki.skullsecurity.org/Passwords).
Both methods will return an associative array containing informations about chars count, keywords and the score.

# Password generation

First, you need to create an instance of the "Generator" class as following:

`$generator = new PHPPasswordToolBox\Generator();`

Random password:

`$generator->generate(12);`

Human readable password generation:

`$generator->setDictionaryPath('dictionary.txt')->generateHumanReadable(12, 2);`

Note that in order to generate human readable passwords you need a dictionary, words in the dictionary must be separated by a break line (\n).
If you are looking for an English word list, give a look [here](https://github.com/dwyl/english-words).

# Password hashing

Simple hash generation:

`PHPPasswordToolBox\Hash::createSimpleHash($password);`

More complex hash generation:

`PHPPasswordToolBox\Hash::createHash($password);`

The first method will return the hash as a string, the second one will return an associative array with the hash and its parameters (salts, algorithm, loop number).
If you need to compare a given password and a hash generated with the first method you can use this method:

`PHPPasswordToolBox\Hash::compareSimpleHash($password, $hash);`

While if you used the second method you can do this:

`PHPPasswordToolBox\Hash::compareHash($password, $hash);`

Are you looking for the Node.js version? Give a look [here](https://github.com/RyanJ93/password-toolbox).

