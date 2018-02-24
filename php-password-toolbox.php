<?php
/**
* A simple toolkit for generate, analyse and hash passwords with PHP.
*
* @package     php-password-toolbox
* @author      Enrico Sola <info@enricosola.com>
* @version     v.1.1.4
*/

namespace PHPPasswordToolBox{
	class Utils{
		/**
		* @const int DEFAULT_CHUNK_SIZE The default size of the chunk (in bytes) to read from files.
		*/
		const DEFAULT_CHUNK_SIZE = 4096;
		
		/**
		* @const int MAX_SIZE_CHARACTER The maximum size (in bytes) of a multi-byte char.
		*/
		const MAX_SIZE_CHARACTER = 4;
		
		/**
		* Splits a given string into a chars array.
		*
		* @param string $string The string that shall be splitted.
		*
		* @return array A sequentiall array of strings containing the string's chars.
		*/
		public static function splitString(string $string): array{
			if ( $string === NULL || $string === '' ){
				return array();
			}
			$length = mb_strlen($string);
			$array = array();
			while ( $length > 0 ){
				$array[] = mb_substr($string, 0, 1);
				$string = mb_substr($string, 1, $length);
				$length = mb_strlen($string); 
			}
			return $array;
		}
		
		/**
		* Reads a chunk from a given file, for more info give a look here: https://github.com/jstewmc/chunker/blob/master/src/File.php#L138
		*
		* @param string $path A string containing the path to the file.
		* @param int $chunkSize An integer number greater than zero that specifies the size (in bytes) of the chunk to read from the file.
		* @param int $page An integer greater than zero that represents the chunk which shall be read from the file.
		* @param string $encoding A string representing the file encoding, if not set will be used the internal encoding ("mb_internal_encoding()").
		*
		* @return string A string containing the chunk read from the file.
		*
		* @throws InvalidArgumentException If the given path is an empty string or NULL.
		* @throws Exception If an error occurs while reading from the given file.
		*/
		public static function readFileChunk(string $path, int $chunkSize = NULL, int $page = NULL, string $encoding = NULL): string{
			if ( $path === NULL || $path === '' ){
				throw new \InvalidArgumentException('Invalid file path.');
			}
			if ( $chunkSize === NULL || $chunkSize <= 0 ){
				$chunkSize = self::DEFAULT_CHUNK_SIZE;
			}
			if ( $page === NULL || $page <= 0 ){
				$page = 1;
			}
			if ( $encoding === NULL || $encoding === '' ){
				$encoding = mb_internal_encoding();
			}
			$start = ( $chunkSize * ( $page - 1 ) ) - self::MAX_SIZE_CHARACTER;
			if ( $start < 0 ){
				$start = 0;
			}
			$length = $chunkSize + self::MAX_SIZE_CHARACTER;
			$data = @file_get_contents($path, false, NULL, $start, $length);
			if ( $data === false ){
				throw new \Exception('Unable to read from the given file.');
			}
			if ( $data === '' ){
				return '';
			}
			$pos = $chunkSize * ( $page - 1 );
			if ( $pos > self::MAX_SIZE_CHARACTER ){
				$pos = self::MAX_SIZE_CHARACTER;
			}
			return mb_strcut($data, $pos, $chunkSize, $encoding);
		}
	}
	
	class Analyzer{
		/**
		* @var string $dictionary A string containing the path to the dictionary file that contains a list of weak passwords separated by a breakline (\n).
		*/
		protected $dictionary = NULL;
		
		/**
		* @var string $wordlist A string containing the content of the dictionary, if it is going to be cached for next uses.
		*/
		protected $wordlist = NULL;
		
		/**
		* @var bool $cache If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		protected $cache = false;
		
		/**
		* @var bool $ci If set to "true", the passwords will be analyzed in case-insensitive way, otherwise not.
		*/
		protected $ci = true;
		
		/**
		* @var int $chunkSize An integer number grater than zero representing the chunk size (in bytes).
		*/
		protected $chunkSize = 4096;
		
		/**
		* @var string $dictionaryEncoding A string representing the encoding of the dictionary file.
		*/
		protected $dictionaryEncoding = NULL;
		
		/**
		* Sets the path to the dictionary file, this method is chainable.
		*
		* @param string $path A string containing the path to the dictionary.
		*/
		public function setDictionaryPath(string $path = NULL): Analyzer{
			if ( $path === '' ){
				$path = NULL;
			}
			if ( $this->dictionary !== $path ){
				$this->wordlist = $this->cache === false ? NULL : '';
				$this->dictionary = $path;
			}
			return $this;
		}
		
		/**
		* Returns the path to the dictionary.
		*
		* @return string A string containing the path to the dictionary.
		*/
		public function getDictionaryPath(): string{
			$dictionary = $this->dictionary;
			return $dictionary === NULL ? '' : $dictionary;
		}
		
		/**
		* Sets if the dictionary cache shall be used or not, this method is chainable.
		*
		* @param bool $value If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		public function setDictionaryCache(bool $value = false): Analyzer{
			if ( $value !== true ){
				$this->cache = false;
				$this->wordlist = NULL;
				return $this;
			}
			$this->cache = true;
			return $this;
		}
		
		/**
		* Returns if the dictionary cache is enabled or not.
		*
		* @return bool If the dictionary cache is enabled will be returned "true", otherwise "false".
		*/
		public function getDictionaryCache(): bool{
			return $this->cache === true ? true : false;
		}
		
		/**
		* Cleares the content of the dictionary cache, this method is chainable.
		*/
		public function invalidateDictionaryCache(): Analyzer{
			$this->wordlist = null;
			return $this;
		}
		
		/**
		* Loads the content of the dictionary that has been set.
		*
		* @return bool If some data is loaded from the file will be returned "true", otherwise "false".
		*
		* @throws Exception If an error occurs while reading dictionary contents.
		*/
		public function loadDictionaryCache(): bool{
			if ( $this->cache === false || $this->dictionary === NULL ){
				return false;
			}
			$data = @file_get_contents($this->dictionary);
			if ( $data === false ){
				throw new \Exception('Unable to load the dictionary.');
			}
			$this->wordlist = $data;
			return true;
		}
		
		/**
		* Sets if the passwords shall be analyzed in case-insensitive way or not, this method is chainable.
		*
		* @param bool $value If set to "true" the passwords will be analyzed in case-insensitive way, otherwise not.
		*/
		public function setCaseInsensitive(bool $value = true): Analyzer{
			$this->ci = $value === false ? false : true;
			return $this;
		}
		
		/**
		* Returns if the passwords shall be analyzed in case-insensitive way or not.
		*
		* @return bool If the passwords will be analyzed in case-insensitive way will be returned "true", otherwise "false".
		*/
		public function getCaseInsensitive(): bool{
			return $this->ci === false ? false : true;
		}
		
		/**
		* Sets the size of the chunk that shall be read from the dictionary file, this method is chainable.
		*
		* @param int $chunkSize An integer number greater than zero representing the chunk size (in bytes), if set to NULL, the default chunk size (4096 bytes) will be used insted.
		*
		* @throws InvalidArgumentException If the given size is lower or equal than zero.
		*/
		public function setChunkSize(int $chunkSize = NULL): Analyzer{
			if ( $chunkSize === NULL ){
				$this->chunkSize = Utils::DEFAULT_CHUNK_SIZE;
				return $this;
			}
			if ( $chunkSize <= 0 ){
				throw new \InvalidArgumentException('Invalid chunk size.');
			}
			$this->chunkSize = $chunkSize;
			return $this;
		}
		
		/**
		* Returns the size of the chunk that shall be read from the dictionary file.
		*
		* @return int An integer number greater than zero representing the chunk size (in bytes).
		*/
		public function getChunkSize(): int{
			return $this->chunkSize;
		}
		
		/**
		* Sets the encoding of the dictionary file, this method is chainable.
		*
		* @param string $encoding A string representing the file encoding, if set to NULL, the internal encoding will be used instead.
		*/
		public function setDictionaryEncoding(string $encoding = NULL): Analyzer{
			$this->dictionaryEncoding = $encoding === '' ? NULL : $encoding;
			return $this;
		}
		
		/**
		* Returns the encoding of the dictionary file.
		*
		* @return string A string representing the file encoding.
		*/
		public function getDictionaryEncoding(): string{
			$encoding = $this->dictionaryEncoding;
			return $encoding === NULL ? '' : $encoding;
		}
		
		/**
		* Analyzes a given password.
		*
		* @param string $password The password to analyze.
		* @param array $keywords An optional sequeantial array of strings containing some keywords which shall be looked into the given password (like first name, surname, e-mail address and so on).
		*
		* @return array An associative array containing the information of the analysis, like chars counts, keywords counts and strength score.
		*/
		public function analyze(string $password, array $keywords = NULL): array{
			$analysis = array(
				'numbers' => 0,
				'uppercaseLetters' => 0,
				'lowercaseLetters' => 0,
				'specialChars' => 0,
				'length' => 0,
				'keywords' => array(),
				'keywordsCount' => 0,
				'keywordsUniqueCount' => 0,
				'score' => 0
			);
			if ( $password === NULL || $password === '' ){
				return $analysis;
			}
			$analysis['length'] = mb_strlen($password);
			$analysis['numbers'] = preg_match_all('/[0-9]/u', $password);
			$analysis['lowercaseLetters'] = preg_match_all('/[a-z]/u', $password);
			$analysis['uppercaseLetters'] = preg_match_all('/[A-Z]/u', $password);
			$analysis['specialChars'] = preg_match_all('/[^A-Za-z0-9]/u', $password);
			$ci = $this->ci === false ? false : true;
			if ( $ci === true ){
				$password = mb_strtolower($password);
			}
			$analysis['score'] = $analysis['length'] < 15 ? - ( floor( ( ( 15 - $analysis['length'] ) * 100 ) / 15 ) ) : 0;
			if ( $analysis['numbers'] === 0 ){
				$analysis['score'] -= 10;
			}
			if ( $analysis['uppercaseLetters'] === 0 ){
				$analysis['score'] -= 10;
			}
			if ( $analysis['lowercaseLetters'] === 0 ){
				$analysis['score'] -= 10;
			}
			if ( $analysis['specialChars'] === 0 ){
				$analysis['score'] -= 5;
			}
			$chars = array();
			$buffer = Utils::splitString($password);
			for ( $i = 0 ; $i < $analysis['length'] ; $i++ ){
				if ( isset($chars[$buffer[$i]]) === true ){
					$chars[$buffer[$i]]++;
				}else{
					$chars[$buffer[$i]] = 0;
				}
			}
			foreach ( $chars as $key => $value ){
				if ( $value !== 0 ){
					$analysis['score'] -= floor(( ( $value * 100 ) / $analysis['length'] ) / 5);
				}
			}
			if ( $keywords !== NULL && array_values($keywords) === $keywords ){
				$keywordsLength = count($keywords);
				if ( $keywordsLength !== 0 ){
					for ( $i = 0 ; $i < $keywordsLength ; $i++ ){
						if ( is_string($keywords[$i]) === false || $keywords[$i] === '' ){
							continue;
						}
						if ( $ci === true ){
							$keywords[$i] = mb_strtolower($keywords[$i]);
						}
						$buffer = mb_substr_count($password, $keywords[$i]);
						$analysis['keywords'][$keywords[$i]] = $buffer;
						if ( $buffer !== 0 ){
							$analysis['keywordsCount'] += $buffer;
							$analysis['keywordsUniqueCount']++;
							$analysis['score'] -= $buffer * 5;
						}
					}
				}
			}
			$analysis['score'] = 100 + $analysis['score'];
			$analysis['score'] = $analysis['score'] > 100 ? 100 : ( $analysis['score'] < 0 ? 0 : $analysis['score'] );
			$analysis['score'] = (int)$analysis['score'];
			return $analysis;
		}
		
		/**
		* Analyzes a given password using also a dictionary of weak passwords to test its strength.
		*
		* @param string $password The password to analyze.
		* @param array $info A sequential array of strings containing some additional information which shall be looked into the given password (like first name, surname, e-mail address and so on).
		*
		* @return array An associative array containing the information of the analysis, like chars counts, keywords counts and strength score.
		*/
		public function completeAnalysis(string $password, array $keywords = NULL): array{
			$analysis = $this->analyze($password, $keywords);
			$dictionary = $this->dictionary;
			if ( $dictionary === NULL ){
				return $analysis;
			}
			if ( $this->ci === true ){
				$password = mb_strtolower($password);
			}
			$dictionaryEncoding = $this->dictionaryEncoding;
			if ( $dictionaryEncoding === NULL ){
				$dictionaryEncoding = mb_internal_encoding();
			}
			if ( $this->cache === true && $this->wordlist !== NULL && $this->wordlist !== '' ){
				if ( mb_strpos($this->wordlist, "\n") === false && $this->wordlist === $password ){
					$analysis['score'] -= $analysis['score'] > 50 ? 25 : 10;
				}elseif ( mb_strpos($this->wordlist, $password . "\n", $dictionaryEncoding) !== false || mb_strpos($this->wordlist, "\n" . $password, $dictionaryEncoding) !== false ){
					$analysis['score'] -= $analysis['score'] > 50 ? 25 : 10;
				}
				$analysis['score'] = $analysis['score'] > 100 ? 100 : ( $analysis['score'] < 0 ? 0 : $analysis['score'] );
				$analysis['score'] = (int)$analysis['score'];
				return $analysis;
			}elseif ( $this->cache === true && ( $this->wordlist !== NULL || $this->wordlist !== '' ) ){
				$data = @file_get_contents($dictionary);
				if ( $data === false ){
					throw new \Exception('Dictionary file was not found.');
				}
				if ( $data === '' ){
					return $analysis;
				}
				$this->wordlist = $data;
				if ( mb_strpos($data, "\n") === false && $data === $password ){
					$analysis['score'] -= $analysis['score'] > 50 ? 25 : 10;
				}elseif ( mb_strpos($data, $password . "\n", 0, $dictionaryEncoding) !== false ){
					$analysis['score'] -= $analysis['score'] > 50 ? 25 : 10;
				}
				$analysis['score'] = $analysis['score'] > 100 ? 100 : ( $analysis['score'] < 0 ? 0 : $analysis['score'] );
				$analysis['score'] = (int)$analysis['score'];
				return $analysis;
			}
			$chunkSize = $this->chunkSize;
			$data = NULL;
			$page = 1;
			while ( $data !== '' ){
				$data = Utils::readFileChunk($dictionary, $chunkSize, $page, $dictionaryEncoding);
				if ( mb_strpos($data, $password . "\n", 0, $dictionaryEncoding) !== false ){
					$analysis['score'] -= $analysis['score'] > 50 ? 25 : 10;
					$analysis['score'] = $analysis['score'] > 100 ? 100 : ( $analysis['score'] < 0 ? 0 : $analysis['score'] );
					$analysis['score'] = (int)$analysis['score'];
					return $analysis;
				}
				$page++;
			}
			return $analysis;
		}
	}
	
	class Generator{
		/**
		* @var string $dictionary A string containing the path to the dictionary file that contains a list of words separated by a breakline (\n).
		*/
		protected $dictionary = NULL;
		
		/**
		* @var string $wordlist A string containing the content of the dictionary, if it is going to be cached for next uses.
		*/
		protected $wordlist = NULL;
		
		/**
		* @var bool $cache If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		protected $cache = false;
		
		/**
		* @var int $chunkSize An integer number grater than zero representing the chunk size (in bytes).
		*/
		protected $chunkSize = 4096;
		
		/**
		* @var string $dictionaryEncoding A string representing the encoding of the dictionary file.
		*/
		protected $dictionaryEncoding = NULL;
		
		/**
		* Sets the path to the dictionary file, this method is chainable.
		*
		* @param string $path A string containing the path to the dictionary.
		*/
		public function setDictionaryPath(string $path = NULL): Generator{
			if ( $path === '' ){
				$path = NULL;
			}
			if ( $this->dictionary !== $path ){
				$this->wordlist = $this->cache === false ? NULL : '';
				$this->dictionary = $path;
			}
			return $this;
		}
		
		/**
		* Returns the path to the dictionary.
		*
		* @return string A string containing the path to the dictionary.
		*/
		public function getDictionaryPath(): string{
			$dictionary = $this->dictionary;
			return $dictionary === NULL ? '' : $dictionary;
		}
		
		/**
		* Sets if the dictionary cache shall be used or not, this method is chainable.
		*
		* @param bool $value If set to "true", the content of the dictionary will be cached for next uses, otherwise not.
		*/
		public function setDictionaryCache(bool $value = false): Generator{
			if ( $value !== true ){
				$this->cache = false;
				$this->wordlist = NULL;
				return $this;
			}
			$this->cache = true;
			return $this;
		}
		
		/**
		* Returns if the dictionary cache is enabled or not.
		*
		* @return bool If the dictionary cache is enabled will be returned "true", otherwise "false".
		*/
		public function getDictionaryCache(): bool{
			return $this->cache === true ? true : false;
		}
		
		/**
		* Cleares the content of the dictionary cache, this method is chainable.
		*/
		public function invalidateDictionaryCache(): Generator{
			$this->wordlist = null;
			return $this;
		}
		
		/**
		* Loads the content of the dictionary that has been set.
		*
		* @return bool If some data is loaded from the file will be returned "true", otherwise "false".
		*
		* @throws Exception If an error occurs while reading dictionary contents.
		*/
		public function loadDictionaryCache(): bool{
			if ( $this->cache === false || $this->dictionary === NULL ){
				return false;
			}
			$data = @file_get_contents($this->dictionary);
			if ( $data === false ){
				throw new \Exception('Unable to load the dictionary.');
			}
			$this->wordlist = $data;
			return true;
		}
		
		/**
		* Sets the size of the chunk that shall be read from the dictionary file, this method is chainable.
		*
		* @param int $chunkSize An integer number greater than zero representing the chunk size (in bytes), if set to NULL, the default chunk size (4096 bytes) will be used insted.
		*
		* @throws InvalidArgumentException If the given size is lower or equal than zero.
		*/
		public function setChunkSize(int $chunkSize = NULL): Generator{
			if ( $chunkSize === NULL ){
				$this->chunkSize = Utils::DEFAULT_CHUNK_SIZE;
				return $this;
			}
			if ( $chunkSize <= 0 ){
				throw new \InvalidArgumentException('Invalid chunk size.');
			}
			$this->chunkSize = $chunkSize;
			return $this;
		}
		
		/**
		* Returns the size of the chunk that shall be read from the dictionary file.
		*
		* @return int An integer number greater than zero representing the chunk size (in bytes).
		*/
		public function getChunkSize(): int{
			return $this->chunkSize;
		}
		
		/**
		* Sets the encoding of the dictionary file, this method is chainable.
		*
		* @param string $encoding A string representing the file encoding, if set to NULL, the internal encoding will be used instead.
		*/
		public function setDictionaryEncoding(string $encoding = NULL): Generator{
			$this->dictionaryEncoding = $encoding === '' ? NULL : $encoding;
			return $this;
		}
		
		/**
		* Returns the encoding of the dictionary file.
		*
		* @return string A string representing the file encoding.
		*/
		public function getDictionaryEncoding(): string{
			$encoding = $this->dictionaryEncoding;
			return $encoding === NULL ? '' : $encoding;
		}
		
		/**
		* Generate a random password long as much as specified.
		*
		* @param int $length An integer number greater than zero representing the password length.
		* @param string $pattern A string containing all possible chars that the password can contain, if not specified, the generated password may contain both letters (a-Z) and numbers.
		*
		* @return string A string containing the generated password.
		*
		* @throw Exception If an error occurs during password generation.
		*/
		public function generate(int $length, string $pattern = NULL): string{
			if ( $length === NULL || $length <= 0 ){
				return '';
			}
			try{
				return Hash::generateRandomToken($length, $pattern);
			}catch(\Exception $ex){
				throw new \Exception('Unable to generate the password.');
			}
		}
		
		/**
		* Generate a random password using a given dictionary.
		*
		* @param int $length An integer number greater than zero representing the password length.
		* @param int $numLength An integer number greater or equal than zero representing the length of an additional numeric string added to the password, if set to 0 or not set no additional string will be generated.
		*
		* @return string A string containing the generated password.
		*
		* @throws Exception If no dictionary has been defined before using this method.
		* @throws Exception If an error occurs while reading data from the dictionary file.
		*/
		public function generateHumanReadable(int $length, int $numLength = NULL): string{
			if ( $length === NULL || $length <= 0 ){
				return '';
			}
			$dictionary = $this->dictionary;
			if ( $dictionary === NULL || $dictionary === '' ){
				throw new \Exception('No dictionary has been defined.');
			}
			$numLength = $numLength <= 0 || $numLength === NULL ? 0 : floor($numLength);
			$number = '';
			if ( $numLength > 0 ){
				if ( $numLength > $length ){
					$length = $numLength;
				}
				$number = Hash::generateRandomToken($numLength, '0123456789');
				if ( $numLength === $length ){
					return $number;
				}
				$length = $length - $numLength;
			}
			$dictionaryEncoding = $this->dictionaryEncoding;
			if ( $dictionaryEncoding === NULL ){
				$dictionaryEncoding = mb_internal_encoding();
			}
			$chunkSize = $this->chunkSize;
			$password = '';
			$length = (int)$length;
			if ( $this->cache === true && $this->wordlist !== NULL ){
				if ( $this->wordlist === '' ){
					return '';
				}
				$len = mb_strlen($this->wordlist, $dictionaryEncoding);
				while ( $password === '' ){
					$portion = Hash::generateRandomNumber(0, $len - $chunkSize);
					$portion = mb_substr($this->wordlist, $portion, $chunkSize, $dictionaryEncoding);
					$buffer = mb_strlen($portion, $dictionaryEncoding);
					if ( mb_substr($portion, $buffer - 1, 1, $dictionaryEncoding) !== "\n" ){
						$portion = mb_substr($portion, 0, mb_strrpos($portion, "\n", NULL, $dictionaryEncoding), $dictionaryEncoding);
					}
					if ( $portion === '' ){
						continue;
					}
					$portion = explode("\n", $portion);
					$buffer = count($portion);
					while ( $password === '' ){
						$buff = $portion[Hash::generateRandomNumber(0, $buffer)];
						if ( mb_strlen($buff, $dictionaryEncoding) === $length ){
							$password = $buff;
							break;
						}
					}
				}
				return Hash::generateRandomNumber(0, 1) === 1 ? $password . $number : $number . $password;
			}
			$data = @file_get_contents($dictionary);
			if ( $data === false ){
				throw new \Exception('Unable to read data from dictionary file.');
			}
			if ( $this->cache === true ){
				$this->wordlist = $data;
			}
			$len = mb_strlen($data, $dictionaryEncoding);
			while ( $password === '' ){
				$portion = Hash::generateRandomNumber(0, $len - $chunkSize);
				$portion = mb_substr($data, $portion, $chunkSize, $dictionaryEncoding);
				$buffer = mb_strlen($portion, $dictionaryEncoding);
				if ( mb_substr($portion, $buffer - 1, 1, $dictionaryEncoding) !== "\n" ){
					$portion = mb_substr($portion, 0, mb_strrpos($portion, "\n", NULL, $dictionaryEncoding), $dictionaryEncoding);
				}
				if ( $portion === '' ){
					continue;
				}
				$portion = explode("\n", $portion);
				$buffer = count($portion);
				while ( $password === '' ){
					$buff = $portion[Hash::generateRandomNumber(0, $buffer)];
					if ( mb_strlen($buff, $dictionaryEncoding) === $length ){
						$password = $buff;
						break;
					}
				}
			}
			return Hash::generateRandomNumber(0, 1) === 1 ? $password . $number : $number . $password;
		}
	}
	
	class Hash{
		/**
		* Generate a random string.
		*
		* @param int $length An integer number greater than zero representing the string length.
		* @param string $pattern A string containing all the chars that can be used in the random string.
		*
		* @return string The generated string.
		*
		* @throws Exception If an error occurs during string generation.
		*/
		public static function generateRandomToken(int $length, string $pattern = NULL): string{
			if ( $length === NULL || $length <= 0 ){
				return '';
			}
			if ( $pattern === NULL || $pattern === '' ){
				$pattern = 'abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789';
			}
			$encoding = mb_detect_encoding($pattern);
			$length = floor($length);
			$ret = '';
			if ( function_exists('random_int') === true ){
				try{
					if ( $encoding === 'ASCII' ){
						$len = strlen($pattern) - 1;
						for ( $i = 0 ; $i < $length ; $i++ ){
							$ret .= $pattern[random_int(0, $len)];
						}
						return $ret;
					}
					$len = mb_strlen($pattern, $encoding) - 1;
					for ( $i = 0 ; $i < $length ; $i++ ){
						$ret .= mb_substr($pattern, random_int(0, $len), 1, $encoding);
					}
					return $ret;
				}catch(\Exception $ex){
					throw new \Exception('Unable to generate the number.');
				}
			}elseif ( function_exists('openssl_random_pseudo_bytes') === true ){
				if ( $encoding === 'ASCII' ){
					$bits = ceil(log(strlen($pattern) - 1, 2));
					$bytes = ceil($bits / 8);
					$bits_max = 1 << $bits;
					for ( $i = 0 ; $i < $length ; $i++ ){
						$buffer = 0;
						do {
							$buffer = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes))) % $bits_max;
							if ( $buffer >= $len ){
								$buffer = $buffer % $len;
							}
							break;
						}while(true);
						$ret .= $pattern[$buffer];
					}
					return $ret;
				}
				$bits = ceil(log(mb_strlen($pattern, $encoding) - 1, 2));
				$bytes = ceil($bits / 8);
				$bits_max = 1 << $bits;
				for ( $i = 0 ; $i < $length ; $i++ ){
					$buffer = 0;
					do {
						$buffer = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes))) % $bits_max;
						if ( $buffer >= $len ){
							$buffer = $buffer % $len;
						}
						break;
					}while(true);
					$ret .= mb_substr($pattern, $buffer, 1, $encoding);
				}
				return $ret;
			}elseif ( function_exists('mt_rand') === true ){
				if ( $encoding === 'ASCII' ){
					$len = strlen($pattern) - 1;
					for ( $i = 0 ; $i < $length ; $i++ ){
						$ret .= $pattern[mt_rand(0, $len)];
					}
					return $ret;
				}
				$len = mb_strlen($pattern, $encoding) - 1;
				for ( $i = 0 ; $i < $length ; $i++ ){
					$ret .= mb_substr($pattern, mt_rand(0, $len), 1, $encoding);
				}
				return $ret;
			}
			if ( $encoding === 'ASCII' ){
				$len = strlen($pattern) - 1;
				for ( $i = 0 ; $i < $length ; $i++ ){
					$ret .= $pattern[rand(0, $len)];
				}
				return $ret;
			}
			$len = mb_strlen($pattern, $encoding) - 1;
			for ( $i = 0 ; $i < $length ; $i++ ){
				$ret .= mb_substr($pattern, rand(0, $len), 1, $encoding);
			}
			return $ret;
		}
		
		/**
		* Generate a random number.
		*
		* @param int $min The minimum number that can be generated.
		* @param int $max The maximum number that can be generated.
		*
		* @return int The generated number.
		*
		* @throws InvalidArgumentException If an invalid minimum or maximum value is passed.
		* @throws Exception If an error occurs during string generation.
		*/
		public static function generateRandomNumber(int $min, int $max): int{
			if ( $min === NULL || $min < 0 ){
				throw new \InvalidArgumentException('Minimum value must be greater or equal than zero.');
			}
			if ( $max === NULL || $max <= 0 ){
				throw new \InvalidArgumentException('Maximum value must be greater than zero.');
			}
			$min = floor($min);
			$max = floor($max);
			if ( $min >= $max ){
				$max = $min + 1;
			}
			if ( function_exists('random_int') === true ){
				try{
					return random_int($min, $max);
				}catch(\Exception $ex){
					throw new \Exception('Unable to generate the number.');
				}
			}elseif ( function_exists('openssl_random_pseudo_bytes') === true ){
			    $range = ( $max - $min ) + 1;
			    $bits = ceil(log($range, 2));
			    $bytes = ceil($bits / 8);
			    $bits_max = 1 << $bits;
			    $num = 0;
			    do {
			        $num = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes))) % $bits_max;
			        if ( $num >= $range ) {
			            $num = $num % $range;
			        }
			        break;
			    } while (true);
			    return $num + $min;
			}elseif ( function_exists('mt_rand') === true ){
				return mt_rand($min, $max);
			}
			return rand($min, $max);
		}
		
		/**
		* Creates an hash from the given password.
		*
		* @param string $password A string containing the password.
		* @param string $algorithm A string cotnaining the algorithm name, is not set, "sha512" will be used.
		*
		* @return string The hashed password.
		*
		* @throws InvalidArgumentException If the given password is invalid.
		* @throws InvalidArgumentException If the given algorithm name is not supported.
		*/
		public static function createSimpleHash(string $password, string $algorithm = NULL): string{
			if ( $password === NULL || $password === '' ){
				throw new \InvalidArgumentException('Invalid password.');
			}
			if ( $algorithm === NULL || $algorithm === '' ){
				$algorithm = 'sha512';
			}
			if ( in_array($algorithm, hash_algos()) === false ){
				throw new \InvalidArgumentException('The algorithm is not supported.');
			}
			return hash($algorithm, $password);
		}
		
		/**
		* Creates a more sophisticated hash using the given password.
		*
		* @param string password A string containing the password.
		* @param array options An associative array containing the additional options for the algorithm.
		*
		* @return array An associative array containing the hashed password and the respective parameters.
		*
		* @throws InvalidArgumentException If the given password is invalid.
		* @throws InvalidArgumentException If the given algorithm name is not supported.
		*/
		public static function createHash(string $password, array $options = NULL): array{
			if ( $password === NULL || $password === '' ){
				throw new \InvalidArgumentException('Invalid password.');
			}
			if ( $options === NULL || array_values($options) === $options ){
				$options = array();
			}
			$algorithm = isset($options['algorithm']) === false || is_string($options['algorithm']) === false || $options['algorithm'] === '' ? 'sha512' : $options['algorithm'];
			if ( in_array($algorithm, hash_algos()) === false ){
				throw new \InvalidArgumentException('The algorithm is not supported.');
			}
			$min = isset($options['minLoopValue']) === false || is_integer($options['minLoopValue']) === false || $options['minLoopValue'] <= 1 ? 1 : $options['minLoopValue'];
			$max = isset($options['maxLoopValue']) === false || is_integer($options['maxLoopValue']) === false || $options['maxLoopValue'] <= 1 ? 1 : $options['maxLoopValue'];
			if ( $min > $max ){
				$max = $min + 1;
			}
			$loop = isset($options['randomLoop']) === true && $options['randomLoop'] === false ? 1 : Hash::generateRandomNumber($min, $max);
			$value = 32;
			if ( isset($options['saltLength']) === true && is_integer($options['saltLength']) === true ){
				$value = $options['saltLength'] <= 1 ? 1 : ( $options['saltLength'] > 256 ? 256 : $options['saltLength'] );
			}
			$salt = isset($options['useSalt']) === true && $options['useSalt'] === false ? '' : Hash::generateRandomToken($value);
			$value = 32;
			if ( isset($options['pepperLength']) === true && is_integer($options['pepperLength']) === true ){
				$value = $options['pepperLength'] <= 1 ? 1 : ( $options['pepperLength'] > 256 ? 256 : $options['pepperLength'] );
			}
			$pepper = isset($options['usePepper']) === true && $options['usePepper'] === false ? '' : Hash::generateRandomToken($value);
			$password = $salt . $password . $pepper;
			for ( $i = 0 ; $i < $loop ; $i++ ){
				$password = hash($algorithm, $password);
			}
			return array(
				'salt' => $salt,
				'pepper' => $pepper,
				'loop' => $loop,
				'password' => password_hash(base64_encode($password), \PASSWORD_DEFAULT),
				'algorithm' => $algorithm
			);
		}
		
		/**
		* Checks if a given password corresponds with the given hash.
		*
		* @param string $password A string containing the password.
		* @param string $hash The hashed password that shall be compared.
		* @param string $algorithm A string containing the name of the algorithm that has been used to hash the original password, if not set "sha512" will be used.
		*
		* @return bool If the given password corresponds will be returned "true", otherwise "false".
		*
		* @throws InvalidArgumentException If the given algorithm name is not supported.
		*/
		public static function compareSimpleHash(string $password, string $hash, string $algorithm = NULL): bool{
			if ( $password === NULL || $password === '' ){
				return false;
			}
			if ( $hash === NULL || $hash === '' ){
				return false;
			}
			try{
				$password = self::createSimpleHash($password, $algorithm);
			}catch(\InvalidArgumentException $ex){
				throw new \InvalidArgumentException('The algorithm is not supported.');
			}
			return hash_equals($hash, $password) === true ? true : false;
		}
		
		/**
		* Checks if a given password corresponds with the given hash as associative array.
		*
		* @param string $password A string containing the password.
		* @param array $hash An associative array containing the password hash and the respective parameters.
		*
		* @return bool If the given password corresponds will be returned "true", otherwise "false".
		*
		* @throws InvalidArgumentException If the given algorithm name is not supported.
		*/
		public static function compareHash(string $password, array $hash): bool{
			if ( $password === NULL || $password === '' ){
				return false;
			}
			if ( $hash === NULL || isset($hash['password']) !== true || $hash['password'] === '' || is_string($hash['password']) === false ){
				return false;
			}
			$algorithm = isset($hash['algorithm']) === false || $hash['algorithm'] === '' || is_string($hash['algorithm']) === false ? 'sha512' : $hash['algorithm'];
			if ( in_array($algorithm, hash_algos()) === false ){
				throw new \InvalidArgumentException('The algorithm is not supported.');
			}
			$loop = isset($hash['loop']) === false || $hash['loop'] <= 1 || is_integer($hash['loop']) === false ? 1 : $hash['loop'];
			$salt = isset($hash['salt']) === false || $hash['salt'] === '' || is_string($hash['salt']) === false ? '' : $hash['salt'];
			$pepper = isset($hash['pepper']) === false || $hash['pepper'] === '' || is_string($hash['pepper']) === false ? '' : $hash['pepper'];
			$password = $salt . $password . $pepper;
			for ( $i = 0 ; $i < $loop ; $i++ ){
				$password = hash($algorithm, $password);
			}
			return password_verify(base64_encode($password), $hash['password']) === true ? true : false;
		}
	}
}
?>