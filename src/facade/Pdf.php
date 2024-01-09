<?php
namespace think\facade;

use think\Facade;

class Pdf extends Facade
{
	protected static function getFacadeClass()
	{
		return \think\Fpdi::class;
	}
}