<?php
namespace WildWolf;

/**
 * @see https://github.com/sjinks/php-cxx/blob/master/test/test_hotp.cpp
 */
abstract class OTP
{
	public static function generateByCounter(string $key, int $counter, string $algo = 'sha1') : int
	{
		$counter = pack('J', $counter);
		$hash    = \hash_hmac($algo, $counter, $key, true);
		return self::getCode($hash);
	}

	public static function generateByTime(string $key, int $window, int $tstamp = null, string $algo = 'sha1') : int
	{
		if ($tstamp === null) {
			$tstamp = \time();
		}

		$counter = (int)($tstamp / $window);
		return self::generateByCounter($key, $counter, $algo);
	}

	public static function generateMultipleByCounter(string $key, int $counter, int $n, string $algo = 'sha1') : array
	{
		$result = [];
		$step   = $n > 0 ? 1 : -1;
		$n      = \abs($n);

		while ($n) {
			$result[] = self::generateByCounter($key, $counter, $algo);
			$counter += $step;
			--$n;
		}

		return $result;
	}

	public static function generateByTimeWindow(string $key, int $window, int $min = -1, int $max = 1, int $tstamp = null, string $algo = 'sha1') : array
	{
		if ($tstamp === null) {
			$tstamp = \time();
		}

		$result  = [];
		$counter = (int)($tstamp / $window) + $min;

		for ($i=$min; $i<=$max; ++$i, ++$counter) {
			$result[] = self::generateByCounter($key, $counter, $algo);
		}

		return $result;
	}

	public static function asOTP(int $code, int $len) : string
	{
		static $powers = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

		if ($len < 1 || $len > 8) {
			throw new \InvalidArgumentException();
		}

		$code = $code % $powers[$len];
		return \str_pad((string)$code, $len, '0', \STR_PAD_LEFT);
	}

	private static function getCode(string $hmac) : int
	{
		$len    = \strlen($hmac);
		$offset = \ord($hmac[$len - 1]) & 0x0F;
		$c1     = \ord($hmac[$offset + 0]);
		$c2     = \ord($hmac[$offset + 1]);
		$c3     = \ord($hmac[$offset + 2]);
		$c4     = \ord($hmac[$offset + 3]);

		return (($c1 & 0x7F) << 24) | ($c2 << 16) | ($c3 << 8) | $c4;
	}
}
