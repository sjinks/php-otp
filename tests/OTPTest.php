<?php

class OTPTest extends PHPUnit\Framework\TestCase
{
	public function rfc6238DataProvider()
	{
		static $seed20 = '12345678901234567890';
		static $seed32 = '12345678901234567890123456789012';
		static $seed64 = '1234567890123456789012345678901234567890123456789012345678901234';

		return [
			[$seed20,          59, 0x00000001, 'sha1',   '94287082'],
			[$seed32,          59, 0x00000001, 'sha256', '46119246'],
			[$seed64,          59, 0x00000001, 'sha512', '90693936'],

			[$seed20,  1111111109, 0x023523EC, 'sha1',   '07081804'],
			[$seed32,  1111111109, 0x023523EC, 'sha256', '68084774'],
			[$seed64,  1111111109, 0x023523EC, 'sha512', '25091201'],

			[$seed20,  1111111111, 0x023523ED, 'sha1',   '14050471'],
			[$seed32,  1111111111, 0x023523ED, 'sha256', '67062674'],
			[$seed64,  1111111111, 0x023523ED, 'sha512', '99943326'],

			[$seed20,  1234567890, 0x0273EF07, 'sha1',   '89005924'],
			[$seed32,  1234567890, 0x0273EF07, 'sha256', '91819424'],
			[$seed64,  1234567890, 0x0273EF07, 'sha512', '93441116'],

			[$seed20,  2000000000, 0x03F940AA, 'sha1',   '69279037'],
			[$seed32,  2000000000, 0x03F940AA, 'sha256', '90698825'],
			[$seed64,  2000000000, 0x03F940AA, 'sha512', '38618901'],

			[$seed20, 20000000000, 0x27BC86AA, 'sha1',   '65353130'],
			[$seed32, 20000000000, 0x27BC86AA, 'sha256', '77737706'],
			[$seed64, 20000000000, 0x27BC86AA, 'sha512', '47863826'],
		];
	}

	/**
	 * @dataProvider rfc6238DataProvider
	 */
	public function testRfc6238TOTP($seed, $time, $step, $algo, $expected)
	{
		$actual = WildWolf\OTP::asOTP(WildWolf\OTP::generateByTime($seed, 30, $time, $algo), 8);
		$this->assertEquals($expected, $actual);
	}

	/**
	 * @dataProvider rfc6238DataProvider
	 */
	public function testRfc6238HOTP($seed, $time, $step, $algo, $expected)
	{
		$actual = WildWolf\OTP::asOTP(WildWolf\OTP::generateByCounter($seed, $step, $algo), 8);
		$this->assertEquals($expected, $actual);
	}

	public function rfc4226DataProvider()
	{
		static $key = '12345678901234567890';
		return [
			[$key, 0, 1284755224, 755224],
			[$key, 1, 1094287082, 287082],
			[$key, 2,  137359152, 359152],
			[$key, 3, 1726969429, 969429],
			[$key, 4, 1640338314, 338314],
			[$key, 5,  868254676, 254676],
			[$key, 6, 1918287922, 287922],
			[$key, 7,   82162583, 162583],
			[$key, 8,  673399871, 399871],
			[$key, 9,  645520489, 520489],
		];
	}

	/**
	 * @dataProvider rfc4226DataProvider
	 */
	public function testRfc4226($secret, $counter, $expected1, $expected2)
	{
		$actual1 = WildWolf\OTP::generateByCounter($secret, $counter);
		$actual2 = WildWolf\OTP::asOTP($actual1, 6);
		$this->assertEquals($expected1, $actual1);
		$this->assertEquals($expected2, $actual2);
	}

	public function asOTPExceptionDataProvider()
	{
		return [[-1, 0, 9, 10]];
	}

	/**
	 * @dataProvider asOTPExceptionDataProvider
	 */
	public function testAsOTPException($len)
	{
		$this->expectException(\InvalidArgumentException::class);
		WildWolf\OTP::asOTP(0, $len);
	}

	public function testGenerateByTimeWindow()
	{
		static $expected = [
			425293533,  942152854, 1576851516, 1289488204, 1663094451,
			1284755224,
			1094287082,  137359152, 1726969429, 1640338314,  868254676
		];

		$actual = \WildWolf\OTP::generateByTimeWindow('12345678901234567890', 30, -5, 5, 5);
		$this->assertSame($expected, $actual);
	}

	public function testEmptyTime()
	{
		static $key = '12345678901234567890';

		do {
			$t1 = (int)(time() / 30);
			$r1 = WildWolf\OTP::generateByTime($key, 30);
			$r2 = WildWolf\OTP::generateByTimeWindow($key, 30, 0, 0);
			$t2 = (int)(time() / 30);

			$this->assertEquals(1, count($r2));
			if ($t1 === $t2) {
				$this->assertEquals($r1, $r2[0]);
			}
		} while ($t1 != $t2);
	}

	public function testGenerateMultipleByCounter()
	{
		static $key = '12345678901234567890';

		$expected = [
			WildWolf\OTP::generateByCounter($key, 0),
			WildWolf\OTP::generateByCounter($key, 1),
			WildWolf\OTP::generateByCounter($key, 2),
			WildWolf\OTP::generateByCounter($key, 3),
		];

		$actual   = WildWolf\OTP::generateMultipleByCounter($key, 0, 4);
		$this->assertSame($expected, $actual);
	}

	public function testGenerateMultipleByCounterNeg()
	{
		static $key = '12345678901234567890';

		$expected = [
			WildWolf\OTP::generateByCounter($key,  0),
			WildWolf\OTP::generateByCounter($key, -1),
			WildWolf\OTP::generateByCounter($key, -2),
			WildWolf\OTP::generateByCounter($key, -3),
		];

		$actual   = WildWolf\OTP::generateMultipleByCounter($key, 0, -4);
		$this->assertSame($expected, $actual);
	}

	public function testGenerateMultipleByCounterZero()
	{
		static $key = '12345678901234567890';

		$expected = [];
		$actual   = WildWolf\OTP::generateMultipleByCounter($key, 0, 0);
		$this->assertSame($expected, $actual);
	}
}
