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

	public function addPwd($pwd,$tempdir, $filename)
	{
		$result = [];
		$pdf = new FpdiProtection();
		$pdf->setProtection([FpdiProtection::PERM_PRINT], '', $pwd, 3);
		$pageCount = $pdf->setSourceFile($filename);
		for ($pageNo = 1; $pageNo <= $pageCount; $pageNo++) {
			$id = $pdf->importPage($pageNo);
			$size = $pdf->getTemplateSize($id);
			$pdf->AddPage($size['orientation'], $size);
			$pdf->useTemplate($id);
		}
		$this->mkdirs($tempdir);
		$pdf->Output('F', $tempdir . '/' . $filename);
		$result['path'] = $tempdir . '/' . $filename;
		return $result;
	}

	public function splitImage($company, $tempdir, $filename, $split_num)
	{
		$result = [];
		if ($tempdir) {
			$tempdir .= '/watermark';
		}
		$this->mkdirs($tempdir);

		[$width, $height] = getimagesize($filename);
		$imageObject = imagecreatefrompng($filename);

		$one_width = $width / $split_num;

		//切割小图的宽高
		$imageWHs = [];
		for ($i = 1; $i <= $split_num; $i++) {
			$imageWHs[] = ['w' => $one_width, 'h' => $height, 'x' => ($i - 1) * $one_width, 'y' => '0'];
		}

		foreach ($imageWHs as $j => $image) {
			$picW = $image['w'];
			$picH = $image['h'];

			//透明背景
			$im = imagecreatetruecolor((int)$picW, (int)$picH) or die("Cannot Initialize new GD image stream");//创建小图像
			imagealphablending($im, false);
			imagesavealpha($im, true);
			$white = imagecolorallocatealpha($im, 255, 255, 255, 127);
			imagefill($im, 0, 0, $white);

			$picX = $image['w'];
			$picY = $image['h'];
			$frameX = 0;
			$frameY = 0;
			$x = $image['x'];
			$y = $image['y'];

			/*
			bool imagecopy( resource dst_im, resource src_im, int dst_x, int dst_y, int src_x, int src_y, int src_w, int src_h )
			参数说明：
			参数 说明
			dst_im 目标图像
			src_im 被拷贝的源图像
			dst_x 目标图像开始 x 坐标
			dst_y 目标图像开始 y 坐标，x,y同为 0 则从左上角开始
			src_x 拷贝图像开始 x 坐标
			src_y 拷贝图像开始 y 坐标，x,y同为 0 则从左上角开始拷贝
			src_w （从 src_x 开始）拷贝的宽度
			src_h （从 src_y 开始）拷贝的高度
			*/
			imagecopy($im, $imageObject, -$frameX, -$frameY, (int)$x, (int)$y, (int)$picX, (int)$picY);//拷贝大图片的一部分到小图片
			$split_path = $tempdir . "/watermark_" . ($j + 1) . ".png";
			imagepng($im, $split_path, 0, 100);//创建小图片到磁盘，输出质量为75（0~100）
			imagedestroy($im);                 //释放与 $im 关联的内存

			$result[] = $split_path;
		}
		imagedestroy($imageObject);//释放与 $imageObject 关联的内存
		return $result;
	}

	public function mkdirs($path, $mode = 0777)
	{
		if (!is_dir(dirname($path))) {
			$this->mkdirs(dirname($path), $mode);
		}
		if (!file_exists($path)) {
			return @mkdir($path, $mode);
		}
	}
}