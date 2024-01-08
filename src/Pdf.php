<?php
namespace think;

use setasign\Fpdi\FpdfTrait;
use setasign\Fpdi\FpdiTrait;

class Pdf extends FpdfTpl
{
	use FpdiTrait;
	use FpdfTrait;

	/**
	 * FPDI version
	 *
	 * @string
	 */
	const VERSION = '2.6.0';
}