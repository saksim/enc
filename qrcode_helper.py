#!/usr/bin/env python
# -*- coding: utf-8 -*-
import traceback
import re
import base64
import zlib
import random
import time
from pathlib import Path
import hashlib
from typing import Optional, Dict, List, Tuple, Any
from cryptography.fernet import Fernet
# 图像处理库
try:
    from PIL import Image, ImageDraw, ImageFont, ImageEnhance
    from PIL.Image import Resampling
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("⚠️ 警告: PIL/Pillow不可用，无法生成图片")


"""
-------------------------------------------------------------------------------
   Description :  鉴于防护目的的加密功能
   Author :       Saksim
   Date :         2025/11/25  16:38
   Software:      PyCharm
   Email:         wh13624@my.brisol.ac.uk
   ATTENTION: 法律合规性声明 (依据中国现行法律法规)
-------------------------------------------------------------------------------
  专利声明：   本代码实现的技术方案受中国专利保护。
  版权声明：   © 2025 Saksim 版权所有。保留所有权利。

  法律依据：
  1. 《反不正当竞争法》第九条：
      - 禁止任何主体通过盗窃、贿赂、欺诈等不正当手段获取、披露或使用本代码
      - 违规者需承担最高人民币500万元的民事赔偿责任
  2. 《刑法》第二百一十九条（侵犯商业秘密罪）：
      - 以不正当手段获取、使用或披露商业秘密，情节严重的，处三年以上十年以下有期徒刑，并处罚金
  3. 《民法典》第一千一百八十五条：
      - 故意侵害知识产权的，权利人有权请求惩罚性赔偿
  4. 《计算机软件保护条例》第二十四条：
      - 未经许可复制、修改、反向工程软件，将承担民事及行政责任

  禁止行为：
  - 禁止逆向工程、反编译、反汇编或任何形式的代码还原操作
  - 禁止未经授权将代码用于商业目的、技术复制或向第三方披露
  - 禁止删除或篡改本法律声明

  合规要求：
  1. 任何接触本代码的人员视为已接受保密义务
  2. 发现代码泄露时，权利人可依据《知识产权海关保护条例》申请海关扣押侵权货物
  3. 司法管辖：因本代码引发的争议由 北京市海淀区人民法院 专属管辖

  免责条款：
  任何违反本声明的行为均与Saksim无关，侵权者自行承担全部法律责任。
-------------------------------------------------------------------------------
"""


class OCRFriendlyProtectSafe4File:
    """
    OCR友好的文件保护类 - 修复密钥选择问题并实现功能分离
    """
    # Base32字母表（只包含A-Z和2-7，移除易混淆字符）
    BASE32_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def __init__(self, key_file_path: str):
        """初始化OCR友好文件保护器

        Args:
            key_file_path: 密钥文件路径
        """
        self.key_file_path = Path(key_file_path)
        self.encryption_key_cache = {}  # 缓存文件与密钥的映射

        # 创建自定义Base32编码器
        self.custom_b32_trans = str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            self.BASE32_ALPHABET
        )
        self.custom_b32_reverse = str.maketrans(
            self.BASE32_ALPHABET,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        )

        # 图片生成配置（优化手机拍摄）
        self.image_config = {
            'page_size': (2480, 3508),  # A4尺寸 @ 300DPI
            'margin': 80,
            'font_size': 42,
            'line_height': 52,
            'chars_per_line': 70,
            'dpi': (300, 300),
            'background_color': 'white',
            'text_color': 'black',
            'header_height': 100,
            'footer_height': 80,
        }

    # ==================== 核心功能1: 文件加密并生成OCR图片 ====================
    def file_to_ocr_images(self,
                           input_file_path: str,
                           output_image_dir: str,
                           key: Optional[str] = None,
                           filename_prefix: str = "secure_page",
                           save_key_info: bool = True) -> Dict[str, Any]:
        """将文件加密并生成OCR友好的图片

        Args:
            input_file_path: 输入文件路径
            output_image_dir: 输出图片目录
            key: 加密密钥（None则自动选择）
            filename_prefix: 图片文件名前缀
            save_key_info: 是否保存密钥信息

        Returns:
            包含处理结果的字典
        """
        try:
            print("=" * 60)
            print("步骤1: 文件加密并生成OCR图片")
            print("=" * 60)

            # 1.1 文件加密为OCR文本
            ocr_text, used_key = self._encrypt_file_to_ocr_text(
                input_file_path, key, save_key_info
            )
            if not ocr_text:
                return {"success": False, "error": "文件加密失败"}

            # 1.2 OCR文本生成图片
            success, generated_images, image_result = self._ocr_text_to_images(
                ocr_text, output_image_dir, filename_prefix
            )

            if not success:
                return {"success": False, "error": "图片生成失败"}

            # 整合结果
            result = {
                "success": True,
                "input_file": input_file_path,
                "output_dir": output_image_dir,
                "used_key": used_key,
                "ocr_text_length": len(ocr_text),
                "total_pages": image_result["total_pages"],
                "chars_per_page": image_result["chars_per_page"],
                "generated_images": [str(p) for p in generated_images],
                "font_size": self.image_config["font_size"],
                "image_config": self.image_config.copy()
            }

            print("✅ 文件加密和图片生成完成!")
            return result

        except Exception as e:
            error_msg = f"文件加密并生成图片失败: {e}"
            print(f"❌ {error_msg}")
            return {"success": False, "error": error_msg}

    def _encrypt_file_to_ocr_text(self,
                                  input_file_path: str,
                                  key: Optional[str] = None,
                                  save_key_info: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """将文件加密为OCR友好的文本"""
        try:
            # 选择或使用提供的密钥
            if key is None:
                key = self._select_random_key()
                if not key:
                    raise ValueError("没有可用的密钥")

            print(f"🔑 使用密钥: {key[:20]}...")

            # 验证密钥格式
            try:
                Fernet(key.encode())
            except Exception as e:
                raise ValueError(f"密钥格式无效: {e}")

            cipher_suite = Fernet(key.encode())

            # 读取并加密文件
            with open(input_file_path, 'rb') as file:
                file_data = file.read()

            print(f"📁 原始文件大小: {len(file_data)} 字节")

            encrypted_data = cipher_suite.encrypt(file_data)
            print(f"🔒 加密后大小: {len(encrypted_data)} 字节")

            # OCR友好编码
            ocr_text = self._ocr_friendly_encode(encrypted_data)
            print(f"📄 OCR文本长度: {len(ocr_text)} 字符")

            # 分析字符使用情况
            char_set = set(ocr_text)
            print(f"🔤 使用的字符集: {''.join(sorted(char_set))}")
            print(f"🔢 字符种类数: {len(char_set)}")

            # 保存密钥信息
            if save_key_info:
                self._save_key_info(input_file_path, key)

            # 缓存密钥映射
            self.encryption_key_cache[input_file_path] = key

            return ocr_text, key

        except Exception as e:
            print(f"❌ 文件加密失败: {e}")
            traceback.print_exc()
            return None, None

    def _ocr_text_to_images(self,
                            ocr_text: str,
                            output_image_dir: str,
                            filename_prefix: str) -> Tuple[bool, List[Path], Dict[str, Any]]:
        """将OCR文本转换为图片"""
        if not PIL_AVAILABLE:
            print("❌ PIL不可用，无法生成图片")
            return False, [], {}

        try:
            # 计算页面容量
            page_capacity = self._calculate_page_capacity()
            print(f"📊 页面容量: {page_capacity['chars_per_page']} 字符/页")

            # 分割文本
            pages = self._split_text_to_pages(ocr_text, page_capacity)
            total_pages = len(pages)
            print(f"📑 总页数: {total_pages} 页")

            # 创建输出目录
            output_dir = Path(output_image_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # 生成图片
            generated_images = []
            successful_pages = 0

            for i, page_content in enumerate(pages):
                page_num = i + 1
                image_path = output_dir / f"{filename_prefix}_{page_num:04d}.png"

                print(f"🖼️ 生成第 {page_num}/{total_pages} 页...")

                if self._create_single_page_image(page_content, page_num, total_pages, image_path):
                    generated_images.append(image_path)
                    successful_pages += 1
                    print(f"✅ 成功生成第 {page_num} 页")
                else:
                    print(f"❌ 第 {page_num} 页生成失败")

                time.sleep(0.1)  # 避免卡机

            # 保存页面信息
            self._save_page_info(output_dir, total_pages, successful_pages, page_capacity)

            result = {
                'total_pages': total_pages,
                'successful_pages': successful_pages,
                'chars_per_page': page_capacity['chars_per_page'],
                'total_chars': len(ocr_text),
                'success_rate': successful_pages / total_pages if total_pages else 0
            }

            success = successful_pages == total_pages
            status = "✅" if success else "⚠️"
            print(f"{status} 图片生成完成: {successful_pages}/{total_pages} 页")

            return success, generated_images, result

        except Exception as e:
            print(f"❌ 图片生成失败: {e}")
            traceback.print_exc()
            return False, [], {}

    # ==================== 核心功能2: 从图片OCR识别并合并文本 ====================
    def images_to_ocr_text(self,
                           image_dir: str,
                           output_text_path: Optional[str] = None) -> Dict[str, Any]:
        """从图片OCR识别并合并文本（预留接口）

        Args:
            image_dir: 图片目录路径
            output_text_path: 输出文本路径（可选）

        Returns:
            包含识别结果的字典
        """
        try:
            print("=" * 60)
            print("步骤2: 从图片OCR识别并合并文本")
            print("=" * 60)
            print("⚠️ 此功能需要安装OCR库（如pytesseract、easyocr等）")
            print("📝 预留接口，待实现具体OCR识别功能")

            # 查找图片文件
            image_dir_path = Path(image_dir)
            image_files = sorted(image_dir_path.glob("*.png"))

            if not image_files:
                return {"success": False, "error": "未找到图片文件"}

            print(f"📷 找到 {len(image_files)} 个图片文件")

            # 这里应该实现OCR识别逻辑
            # 目前返回模拟结果
            result = {
                "success": True,
                "message": "OCR识别功能待实现",
                "image_count": len(image_files),
                "image_files": [str(f) for f in image_files],
                "extracted_text": "",  # 实际应该包含识别出的文本
                "output_path": output_text_path
            }

            # 如果提供了输出路径，保存提示信息
            if output_text_path:
                with open(output_text_path, 'w', encoding='utf-8') as f:
                    f.write("# OCR识别功能待实现\n")
                    f.write(f"# 共找到 {len(image_files)} 个图片文件\n")
                    f.write(f"# 需要安装OCR库并实现识别逻辑\n")

            return result

        except Exception as e:
            error_msg = f"图片OCR识别失败: {e}"
            print(f"❌ {error_msg}")
            return {"success": False, "error": error_msg}

    # ==================== 核心功能3: 从OCR文本解密文件 ====================
    def ocr_text_to_file(self,
                         input_text_path: str,
                         output_file_path: str,
                         key: Optional[str] = None,
                         original_file_path: Optional[str] = None) -> Dict[str, Any]:
        """从OCR文本解密文件

        Args:
            input_text_path: 输入OCR文本路径
            output_file_path: 输出文件路径
            key: 解密密钥（None则自动查找）
            original_file_path: 原始文件路径（用于密钥查找）

        Returns:
            包含解密结果的字典
        """
        try:
            print("=" * 60)
            print("步骤3: 从OCR文本解密文件")
            print("=" * 60)

            # 查找密钥
            if key is None:
                key = self._find_decryption_key(input_text_path, original_file_path)
                if not key:
                    return {"success": False, "error": "未找到解密密钥"}

            print(f"🔑 使用密钥解密: {key[:20]}...")

            # 验证密钥格式
            try:
                cipher_suite = Fernet(key.encode())
            except Exception as e:
                return {"success": False, "error": f"密钥格式无效: {e}"}

            # 读取OCR文本
            with open(input_text_path, 'r', encoding='utf-8') as f:
                ocr_text = f.read().strip()

            print(f"📄 读取OCR文本: {len(ocr_text)} 字符")

            # OCR友好解码
            encrypted_data = self._ocr_friendly_decode(ocr_text)
            print(f"🔒 解码后加密数据: {len(encrypted_data)} 字节")

            # Fernet解密
            file_data = cipher_suite.decrypt(encrypted_data)
            print(f"📁 解密后文件大小: {len(file_data)} 字节")

            # 保存文件
            with open(output_file_path, 'wb') as f:
                f.write(file_data)

            # 验证文件完整性
            verification = self._verify_file_integrity(original_file_path, output_file_path)

            result = {
                "success": True,
                "output_file": output_file_path,
                "file_size": len(file_data),
                "verification": verification
            }

            print("✅ 文件解密完成!")
            return result

        except Exception as e:
            error_msg = f"文件解密失败: {e}"
            print(f"❌ {error_msg}")
            traceback.print_exc()
            return {"success": False, "error": error_msg}

    def _verify_file_integrity(self,
                               original_path: Optional[str],
                               decrypted_path: str) -> Dict[str, Any]:
        """验证文件完整性"""
        try:
            if not original_path or not Path(original_path).exists():
                return {"verified": False, "reason": "原始文件不存在"}

            original_size = Path(original_path).stat().st_size
            decrypted_size = Path(decrypted_path).stat().st_size

            result = {
                "size_match": original_size == decrypted_size,
                "original_size": original_size,
                "decrypted_size": decrypted_size
            }

            if original_size == decrypted_size:
                # 计算MD5验证
                with open(original_path, 'rb') as f1, open(decrypted_path, 'rb') as f2:
                    original_hash = hashlib.md5(f1.read()).hexdigest()
                    decrypted_hash = hashlib.md5(f2.read()).hexdigest()

                result["hash_match"] = original_hash == decrypted_hash
                result["original_hash"] = original_hash
                result["decrypted_hash"] = decrypted_hash

                if original_hash == decrypted_hash:
                    result["verified"] = True
                    result["message"] = "文件完整性验证通过"
                else:
                    result["verified"] = False
                    result["message"] = "文件内容不匹配"
            else:
                result["verified"] = False
                result["message"] = "文件大小不匹配"

            return result

        except Exception as e:
            return {"verified": False, "error": str(e)}

    # ==================== 工具方法 ====================
    def _select_random_key(self) -> Optional[str]:
        """随机选择有效的密钥"""
        keys = self._load_keys_from_file()
        if not keys:
            return None
        # 验证密钥有效性
        valid_keys = []
        for key in keys:
            try:
                Fernet(key.encode())  # 验证密钥格式
                valid_keys.append(key)
            except:
                continue  # 跳过无效密钥
        if not valid_keys:
            print("❌ 密钥文件中没有有效的密钥")
            return None
        return random.choice(valid_keys)

    def _load_keys_from_file(self) -> List[str]:
        """从文件加载所有密钥"""
        try:
            with open(self.key_file_path, 'r') as f:
                keys = [line.strip() for line in f.readlines() if line.strip()]
            print(f"✅ 从 {self.key_file_path} 加载了 {len(keys)} 个密钥")
            return keys
        except FileNotFoundError:
            print(f"❌ 密钥文件不存在: {self.key_file_path}")
            return []

    def _find_decryption_key(self, text_path: str, original_path: Optional[str]) -> Optional[str]:
        """查找解密密钥"""
        # 1. 尝试从缓存获取
        if original_path and original_path in self.encryption_key_cache:
            return self.encryption_key_cache[original_path]
        # 2. 尝试从.keyinfo文件获取
        keyinfo_path = text_path + ".keyinfo"
        key = self._load_key_from_keyinfo(keyinfo_path)
        if key:
            return key
        # 3. 返回第一个可用密钥
        keys = self._load_keys_from_file()
        valid_keys = [k for k in keys if self._is_valid_key(k)]
        return valid_keys[0] if valid_keys else None

    def _is_valid_key(self, key: str) -> bool:
        """验证密钥是否有效"""
        try:
            Fernet(key.encode())
            return True
        except:
            return False

    def _load_key_from_keyinfo(self, keyinfo_path: str) -> Optional[str]:
        """从.keyinfo文件加载密钥"""
        try:
            with open(keyinfo_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('KEY:'):
                        key = line.strip().replace('KEY:', '')
                        if self._is_valid_key(key):
                            return key
            return None
        except FileNotFoundError:
            return None

    def _save_key_info(self, file_path: str, key: str) -> None:
        """保存密钥信息"""
        keyinfo_path = file_path + ".keyinfo"
        with open(keyinfo_path, 'w', encoding='utf-8') as f:
            f.write(f"FILE:{file_path}\n")
            f.write(f"KEY:{key}\n")
            f.write(f"TIMESTAMP:{time.time()}\n")
        print(f"🔑 密钥信息已保存: {keyinfo_path}")

    def _save_page_info(self, output_dir: Path, total_pages: int,
                        successful_pages: int, page_capacity: Dict) -> None:
        """保存页面信息"""
        info_file = output_dir / "page_info.txt"
        with open(info_file, 'w', encoding='utf-8') as f:
            f.write(f"总页数: {total_pages}\n")
            f.write(f"成功生成: {successful_pages}\n")
            f.write(f"页面容量: {page_capacity['chars_per_page']}\n")
            f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ==================== 编码/解码方法 ====================
    def _ocr_friendly_encode(self, data: bytes) -> str:
        """OCR友好编码"""
        compressed = zlib.compress(data, level=9)
        encoded = self._base32_custom_encode(compressed)
        return self._add_checksum(encoded)

    def _ocr_friendly_decode(self, encoded_str: str) -> bytes:
        """OCR友好解码"""
        data_part = self._verify_checksum(encoded_str)
        if not data_part:
            raise ValueError("校验和验证失败")
        decoded = self._base32_custom_decode(data_part)
        return zlib.decompress(decoded)

    def _base32_custom_encode(self, data: bytes) -> str:
        """自定义Base32编码"""
        standard_b32 = base64.b32encode(data).decode('ascii').rstrip('=')
        return standard_b32.translate(self.custom_b32_trans)

    def _base32_custom_decode(self, encoded_str: str) -> bytes:
        """自定义Base32解码"""
        standard_b32 = encoded_str.translate(self.custom_b32_reverse)
        padding = 8 - len(standard_b32) % 8
        if padding != 8:
            standard_b32 += '=' * padding
        return base64.b32decode(standard_b32)

    def _add_checksum(self, data: str) -> str:
        """添加校验和"""
        checksum = sum(ord(c) for c in data) % 100
        return f"{data}{checksum:02d}"

    def _verify_checksum(self, data: str) -> Optional[str]:
        """验证校验和"""
        if len(data) < 3:
            return None
        main_data = data[:-2]
        expected_checksum = sum(ord(c) for c in main_data) % 100
        provided_checksum = int(data[-2:])
        return main_data if expected_checksum == provided_checksum else None

    # ==================== 图片生成相关方法 ====================
    def _calculate_page_capacity(self) -> Dict[str, int]:
        """计算页面容量"""
        config = self.image_config
        usable_width = config['page_size'][0] - 2 * config['margin']
        usable_height = config['page_size'][1] - config['header_height'] - config['footer_height']
        chars_per_line = min(config['chars_per_line'],
                             int(usable_width // (config['font_size'] * 0.6)))
        lines_per_page = int(usable_height // config['line_height'])
        return {
            'chars_per_line': chars_per_line,
            'lines_per_page': lines_per_page,
            'chars_per_page': chars_per_line * lines_per_page
        }

    def _split_text_to_pages(self, text: str, page_capacity: Dict) -> List[str]:
        """分割文本为多页"""
        chars_per_page = page_capacity['chars_per_page']
        return [text[i:i + chars_per_page] for i in range(0, len(text), chars_per_page)]

    def _create_single_page_image(self, content: str, page_num: int,
                                  total_pages: int, output_path: Path) -> bool:
        """创建单页图片"""
        if not PIL_AVAILABLE:
            return False
        try:
            config = self.image_config
            width, height = config['page_size']
            margin = config['margin']
            # 创建图片
            img = Image.new('RGB', (width, height), color=config['background_color'])
            draw = ImageDraw.Draw(img)
            font = self._get_font(config['font_size'])
            # 绘制页眉
            header_text = f"Page {page_num}/{total_pages}"
            bbox = draw.textbbox((0, 0), header_text, font=font)
            header_width = bbox[2] - bbox[0]
            header_x = (width - header_width) // 2
            header_y = margin // 2
            draw.text((header_x, header_y), header_text, font=font, fill=config['text_color'])
            # 绘制分隔线
            header_line_y = margin + 20
            draw.line([(margin, header_line_y), (width - margin, header_line_y)],
                      fill='gray', width=2)
            # 计算内容区域
            content_start_y = header_line_y + 30
            # 分行绘制内容
            x = margin
            y = content_start_y
            chars_per_line = self._calculate_page_capacity()['chars_per_line']
            for i in range(0, len(content), chars_per_line):
                line = content[i:i + chars_per_line]
                # 检查是否超出页面
                if y + config['line_height'] > height - config['footer_height']:
                    break
                draw.text((x, y), line, font=font, fill=config['text_color'])
                y += config['line_height']
            # 绘制页脚
            footer_y = height - config['footer_height']
            draw.line([(margin, footer_y), (width - margin, footer_y)],
                      fill='gray', width=2)
            # 页脚信息
            footer_text = f"Checksum: {hashlib.md5(content.encode()).hexdigest()[:8]}"
            draw.text((margin, footer_y + 10), footer_text, font=font, fill='gray')
            # 保存图片
            img.save(output_path, 'PNG', dpi=config['dpi'], optimize=True)
            return True
        except Exception as e:
            print(f"❌ 生成图片失败: {e}")
            return False

    def _get_font(self, size: int):
        """获取字体"""
        try:
            return ImageFont.truetype("arial.ttf", size)
        except:
            try:
                return ImageFont.truetype("Courier New.ttf", size)
            except:
                return ImageFont.load_default()


# ==================== 使用示例和演示 ====================
def demo_complete_workflow():
    """演示完整工作流程"""
    # 配置路径
    config = {
        'key_file': r"C:\Users\Administrator\Desktop\saksim\加密密钥.txt",
        'input_file': r"D:\20251125\app_ess.rar",
        'image_dir': r"D:\20251125\workflow_images",
        'output_file': r"D:\20251125\workflow_output.rar"
    }
    # 创建处理器
    protector = OCRFriendlyProtectSafe4File(config['key_file'])
    print("🎯 OCR友好文件保护系统 - 完整工作流程演示")
    print("=" * 60)
    # 步骤1: 文件加密并生成图片
    result1 = protector.file_to_ocr_images(
        input_file_path=config['input_file'],
        output_image_dir=config['image_dir'],
        filename_prefix="secure_doc"
    )
    if not result1.get('success', False):
        print("❌ 步骤1失败")
        return False
    print("✅ 步骤1完成")
    print(f"   生成页数: {result1['total_pages']}")
    print(f"   每页字符: {result1['chars_per_page']}")
    # 步骤2: 从图片OCR识别（预留功能）
    result2 = protector.images_to_ocr_text(config['image_dir'])
    if not result2.get('success', False):
        print("⚠️ 步骤2为预留功能")
    else:
        print("✅ 步骤2完成（模拟）")
    # 步骤3: 从OCR文本解密文件
    # 注意：这里我们使用密钥信息文件进行解密
    temp_text_path = config['input_file'] + "_temp.txt"
    result3 = protector.ocr_text_to_file(
        input_text_path=temp_text_path,
        output_file_path=config['output_file'],
        original_file_path=config['input_file']
    )
    if result3.get('success', False):
        print("✅ 步骤3完成")
        verification = result3.get('verification', {})
        if verification.get('verified'):
            print("🎉 文件完整性验证通过!")
        else:
            print("⚠️ 文件验证结果:", verification.get('message', '未知'))
        return True
    else:
        print("❌ 步骤3失败")
        return False


def demo_individual_steps():
    """演示独立功能步骤"""
    config = {
        'key_file': r"C:\Users\Administrator\Desktop\saksim\加密密钥.txt",
        'input_file': r"D:\20251125\app_ess.rar",
        'image_dir': r"D:\20251125\demo_images",
        'output_file': r"D:\20251125\demo_output.rar"
    }
    # 验证密钥文件
    if not Path(config['key_file']).exists():
        print(f"❌ 密钥文件不存在: {config['key_file']}")
        return False
    protector = OCRFriendlyProtectSafe4File(config['key_file'])
    # 验证密钥文件内容
    keys = protector._load_keys_from_file()
    if not keys:
        print("❌ 密钥文件为空或无法读取")
        return False
    print("🔧 独立功能步骤演示")
    print("=" * 60)
    # 只执行步骤1
    result = protector.file_to_ocr_images(
        input_file_path=config['input_file'],
        output_image_dir=config['image_dir'],
        filename_prefix="demo_page"
    )
    if result.get('success', False):
        print("✅ 独立步骤执行成功")
        print(f"   生成的图片: {len(result.get('generated_images', []))} 个")
        print(f"   使用的密钥: {result.get('used_key', '未知')[:30]}...")
        return True
    else:
        print("❌ 独立步骤执行失败")
        print(f"   错误信息: {result.get('error', '未知错误')}")
        return False


if __name__ == "__main__":
    # 运行独立步骤演示
    print("开始独立步骤演示...")
    success = demo_individual_steps()
    if success:
        print("\n" + "=" * 60)
        print("开始完整工作流程演示")
        print("=" * 60)
        # 运行完整演示
        success2 = demo_complete_workflow()
        if success2:
            print("\n🎉 所有演示成功完成!")
        else:
            print("\n💥 完整工作流程演示失败")
    else:
        print("\n💥 独立步骤演示失败")
