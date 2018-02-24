<?php
require dirname(__FILE__) . '/php-password-toolbox.php';

//Generating a password.
$generator = new PHPPasswordToolBox\Generator();
$password = $generator->generate(12);
echo 'Random password: ' . $password . PHP_EOL;

//Generating a human readable password.
$psw = $generator->setDictionaryPath(dirname(__FILE__) . '/dictionary.txt')->generateHumanReadable(12, 2);
echo 'Human readable password: ' . $psw . PHP_EOL;

//Analyzing password.
$analyzer = new PHPPasswordToolBox\Analyzer();
$analysis = $analyzer->analyze($password);
var_dump($analysis);

//Complete password analysis.
$analysis = $analyzer->setDictionaryPath(dirname(__FILE__) . '/rockyou.txt')->completeAnalysis($password);
var_dump($analysis);

//Creating a hash from the password.
$hash = PHPPasswordToolBox\Hash::createSimpleHash($password);
var_dump($hash);

//Comparing the created hash with the original password.
$result = PHPPasswordToolBox\Hash::compareSimpleHash($password, $hash);
var_dump($result);

//Creating a more complex hash.
$hash = PHPPasswordToolBox\Hash::createHash($password);
var_dump($hash);

//Comparing the new hash with the original password.
$result = PHPPasswordToolBox\Hash::compareHash($password, $hash);
var_dump($result);
?>