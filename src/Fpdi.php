<?php

namespace think;

use setasign\Fpdi\FpdfTrait;
use setasign\Fpdi\FpdiTrait;
use setasign\FpdiProtection\FpdiProtection;

class Fpdi extends FpdfTpl
{
	use FpdiTrait;
	use FpdfTrait;

	/**
	 * FPDI version
	 *
	 * @string
	 */
	public const VERSION = '2.6.0';
}