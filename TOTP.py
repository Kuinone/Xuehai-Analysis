import base64
import hashlib
import hmac
import random
import time
from struct import pack

# 常量定义（与Java完全一致）
CODE_DIGITS = 6
TIME_STEP = 60
# 字符集：数字+小写字母+大写字母
CHAR_SET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class TotpUtils:
    @staticmethod
    def create_device_random_text(length: int, device_id: str) -> str:
        """
        生成设备随机文本（大写）
        :param length: 生成长度
        :param device_id: 设备ID（原Java中BaseApplication.getInstance().getDeviceId()）
        :return: 大写随机字符串
        """
        # 第一层随机
        random_str1 = ''.join(random.choice(CHAR_SET) for _ in range(length))
        # 拼接设备ID
        seed = random_str1 + device_id
        # 第二层随机 + 转大写
        random_str2 = ''.join(random.choice(CHAR_SET) for _ in range(length))
        return random_str2.upper()

    @staticmethod
    def _get_current_interval(time_step: int) -> int:
        """获取当前时间间隔"""
        if time_step < 0:
            time_step = TIME_STEP
        return int(time.time() // time_step)

    @staticmethod
    def _left_padding(s: str, length: int) -> str:
        """左补0，直到达到指定长度"""
        return s.zfill(length)

    @staticmethod
    def _right_padding(s: str, length: int) -> str:
        """右补0，直到达到指定长度"""
        return s.ljust(length, '0')

    @staticmethod
    def _hmac_sha(data: bytes, secret: str) -> bytes:
        """
        HMAC-SHA1 加密
        :param data: 时间数据
        :param secret: Base32编码的密钥
        :return: 加密后的字节数组
        """
        # Base32解码密钥
        secret_bytes = base64.b32decode(secret)
        # 初始化HMAC-SHA1
        mac = hmac.new(secret_bytes, data, hashlib.sha1)
        return mac.digest()

    @staticmethod
    def generate_totp(secret: str, time_step: int, digits: int) -> str:
        """
        生成TOTP动态口令
        :param secret: Base32编码的密钥
        :param time_step: 时间步长（秒）
        :param digits: 口令位数
        :return: 指定位数的TOTP字符串
        """
        # 校验位数（1-18位）
        if not 1 <= digits <= 18:
            raise UnsupportedOperationException(f"不支持{digits}位数的动态口令")

        # 获取时间间隔，转为8字节大端字节数组
        interval = TotpUtils._get_current_interval(time_step)
        data = pack('>Q', interval)

        # HMAC-SHA1计算
        hmac_result = TotpUtils._hmac_sha(data, secret)

        # 核心算法：动态截取
        offset = hmac_result[-1] & 0x0F
        binary = (
                ((hmac_result[offset] & 0x7F) << 24)
                | ((hmac_result[offset + 1] & 0xFF) << 16)
                | ((hmac_result[offset + 2] & 0xFF) << 8)
                | (hmac_result[offset + 3] & 0xFF)
        )

        # 取模获取指定位数
        mod = int('1' + '0' * digits)
        otp = binary % mod

        # 左补0返回
        return TotpUtils._left_padding(str(otp), digits)

    @staticmethod
    def verify(secret: str, code: str, time_step: int, digits: int = CODE_DIGITS) -> bool:
        """
        校验TOTP口令（兼容原Java双参数重载）
        原Java逻辑：循环2次校验相同值（修复后保留原逻辑）
        """
        # 对齐原Java代码逻辑：循环2次验证
        for _ in range(2):
            if TotpUtils.generate_totp(secret, time_step, digits) == code:
                return True
        return False


# 自定义异常（与Java对应）
class UnsupportedOperationException(Exception):
    pass

print(TotpUtils.generate_totp("GYZWCYTCMMZGELJUMVRWGLJUMJRGILLBGJRTQLJVMVQTQNJXMRSTENJRHFRXITDY",60,6))