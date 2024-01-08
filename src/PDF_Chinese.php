<?php

namespace think;

class PDF_Chinese extends Fpdf
{

	/**
	 * @throws \Exception
	 */
	public function AddGBFont($family = 'GB', $name = 'STSongStd-Light-Acro'): void
	{
		$cw = [
			' ' => 207, '!' => 270, '"' => 342, '#' => 467, '$' => 462, '%' => 797, '&' => 710, '\'' => 239,
			'(' => 374, ')' => 374, '*' => 423, '+' => 605, ',' => 238, '-' => 375, '.' => 238, '/' => 334, '0' => 462, '1' => 462,
			'2' => 462, '3' => 462, '4' => 462, '5' => 462, '6' => 462, '7' => 462, '8' => 462, '9' => 462, ':' => 238, ';' => 238,
			'<' => 605, '=' => 605, '>' => 605, '?' => 344, '@' => 748, 'A' => 684, 'B' => 560, 'C' => 695, 'D' => 739, 'E' => 563,
			'F' => 511, 'G' => 729, 'H' => 793, 'I' => 318, 'J' => 312, 'K' => 666, 'L' => 526, 'M' => 896, 'N' => 758, 'O' => 772,
			'P' => 544, 'Q' => 772, 'R' => 628, 'S' => 465, 'T' => 607, 'U' => 753, 'V' => 711, 'W' => 972, 'X' => 647, 'Y' => 620,
			'Z' => 607, '[' => 374, '\\' => 333, ']' => 374, '^' => 606, '_' => 500, '`' => 239, 'a' => 417, 'b' => 503, 'c' => 427,
			'd' => 529, 'e' => 415, 'f' => 264, 'g' => 444, 'h' => 518, 'i' => 241, 'j' => 230, 'k' => 495, 'l' => 228, 'm' => 793,
			'n' => 527, 'o' => 524, 'p' => 524, 'q' => 504, 'r' => 338, 's' => 336, 't' => 277, 'u' => 517, 'v' => 450, 'w' => 652,
			'x' => 466, 'y' => 452, 'z' => 407, '{' => 370, '|' => 258, '}' => 370, '~' => 605,
		];
		$CMap = 'GBKp-EUC-H';
		$registry = ['ordering' => 'GB1', 'supplement' => 2];
		$this->AddCIDFonts($family, $name, $cw, $CMap, $registry);
	}

	/**
	 * @throws \Exception
	 */
	public function AddCIDFonts($family, $name, $cw, $CMap, $registry): void
	{
		$this->AddCIDFont($family, '', $name, $cw, $CMap, $registry);
		$this->AddCIDFont($family, 'B', $name . ',Bold', $cw, $CMap, $registry);
		$this->AddCIDFont($family, 'I', $name . ',Italic', $cw, $CMap, $registry);
		$this->AddCIDFont($family, 'BI', $name . ',BoldItalic', $cw, $CMap, $registry);
	}

	/**
	 * @throws \Exception
	 */
	public function AddCIDFont($family, $style, $name, $cw, $CMap, $registry): void
	{
		$fontkey = strtolower($family) . strtoupper($style);
		if (isset($this->fonts[$fontkey])) {
			$this->Error("字体已添加: $family $style");
		}
		$i = count($this->fonts) + 1;
		$name = str_replace(' ', '', $name);
		$this->fonts[$fontkey] = ['i' => $i, 'type' => 'Type0', 'name' => $name, 'up' => -130, 'ut' => 40, 'cw' => $cw, 'CMap' => $CMap, 'registry' => $registry];
	}

	/**
	 * @throws \Exception
	 */
	public function Error($msg): void
	{
		throw new \RuntimeException('FPDF错误: ' . $msg);
	}

}


