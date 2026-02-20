#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全事件列表获取脚本
基于接口文档：/api/xdr/v1/incidents/list
支持HMAC-SHA256签名认证（AK/SK或联动码）
"""

import binascii
import hashlib
import hmac
import json
import struct
import urllib.parse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

# 认证相关常量
EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
TOTAL_STR = "HMAC-SHA256\n%s\n%s"
AUTH_HEADER_KEY = "Authorization"
SDK_HOST_KEY = "sdk-host"
CONTENT_TYPE_KEY = "content-type"
SDK_CONTENT_TYPE_KEY = "sdk-content-type"
DEFAULT_CONTENT_TYPE = "application/json"
SIGN_DATE_KEY = "sign-date"
AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
AUTH_CODE_PARAMS_NUM = 14


class Signature:
    """HMAC-SHA256签名认证类"""

    def __init__(self, auth_code: Optional[str] = None, ak: Optional[str] = None, sk: Optional[str] = None):
        """
        初始化签名对象

        Args:
            auth_code: 联动码（优先使用）
            ak: Access Key
            sk: Secret Key
        """
        if ak and sk:
            self.__access_key = ak
            self.__secret_key = sk
        elif auth_code:
            self.__access_key, self.__secret_key = self.__decode_auth_code(auth_code)
        else:
            raise Exception("必须提供auth_code或ak/sk")

    def signature(self, req: requests.Request) -> None:
        """
        对请求进行签名

        Args:
            req: requests.Request对象
        """
        if not self.__access_key or not self.__secret_key:
            raise Exception("ak/sk不能为空")
        if not req.url or not req.method:
            raise Exception("请求URL和方法不能为空")

        # 处理请求数据
        payload = ""
        if req.data:
            payload = req.data
        elif req.json:
            payload = json.dumps(req.json)

        # 获取主机信息
        host = self.__get_host(req.url)

        # 检查并设置请求头
        req.headers, sign_date = self.__header_check(req.headers, host)

        # 处理签名头
        header_str, sign_header_str = self.__sign_header_handler(req.headers)

        # 生成规范字符串
        canonical_str = self.__get_canonical_str(
            req.method, req.url, req.params, header_str, payload, sign_header_str
        )

        # 计算SHA256哈希
        hashed_canonical_request = self.__sha256_hex_upper(canonical_str.encode("utf-8"))

        # 计算HMAC-SHA256签名
        total_str = TOTAL_STR % (sign_date, hashed_canonical_request)
        signature = self.__hmac_sha256_hex(self.__secret_key, total_str)

        # 设置认证头
        req.headers[AUTH_HEADER_KEY] = EXTEND_HEADER % (self.__access_key, sign_header_str, signature)

    def __decode_auth_code(self, auth_code: str) -> tuple:
        """解码联动码获取AK/SK"""
        builder_str = self.__reverse_hex(auth_code)
        builders = str.split(builder_str.decode("utf-8"), "|")
        if len(builders) != AUTH_CODE_PARAMS_NUM:
            raise Exception("联动码格式错误")

        aes_secret = self.__calculate_aes_secret(builders)
        ak = self.__aes_cbc_decrypt(builders[9], aes_secret)
        sk = self.__aes_cbc_decrypt(builders[10], aes_secret)
        return ak, sk

    @staticmethod
    def __calculate_aes_secret(builders: list) -> bytes:
        """计算AES密钥"""
        build_str = AUTH_CODE_PARAMS % (
            builders[0], builders[1], builders[2], builders[3],
            builders[4], builders[5], builders[6], builders[11],
        )
        return hashlib.sha256(build_str.encode("utf-8")).digest()

    @staticmethod
    def __get_host(uri: str) -> str:
        """从URL获取主机信息"""
        parsed_url = urllib.parse.urlparse(uri)
        return parsed_url.netloc

    @staticmethod
    def __header_check(headers: Dict, host: str) -> tuple:
        """检查并设置请求头"""
        if headers is None:
            headers = {}
        elif not isinstance(headers, dict):
            raise Exception("请求头格式错误")

        if SDK_HOST_KEY not in headers:
            headers[SDK_HOST_KEY] = host

        if CONTENT_TYPE_KEY not in headers:
            headers[SDK_CONTENT_TYPE_KEY] = DEFAULT_CONTENT_TYPE
        else:
            headers[SDK_CONTENT_TYPE_KEY] = headers[CONTENT_TYPE_KEY]

        if SIGN_DATE_KEY not in headers:
            sign_date = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            headers[SIGN_DATE_KEY] = sign_date
        else:
            sign_date = headers[SIGN_DATE_KEY]

        return headers, sign_date

    @staticmethod
    def __sign_header_handler(headers: Dict) -> tuple:
        """处理签名头"""
        header_keys = [(k, v) for k, v in headers.items()]
        header_keys.sort(key=lambda x: x[0].lower())

        header_builder = []
        sign_header_builder = []

        for key, value in header_keys:
            header_builder.append(f"{key}:{value}\n")
            sign_header_builder.append(f"{key};")

        sign_header_str = "".join(sign_header_builder)
        header_str = "".join(header_builder)

        if sign_header_str:
            sign_header_str = sign_header_str[:-1]

        return header_str, sign_header_str

    def __get_canonical_str(self, method: str, uri: str, params: Dict, headers_str: str,
                           payload: str, sign_header_str: str) -> str:
        """生成规范字符串"""
        builder = []
        builder.append(method)
        builder.append("\n")
        builder.append(self.__url_transform(uri))
        builder.append("\n")
        builder.append(self.__query_str_transform(params))
        builder.append("\n")
        builder.append(headers_str)
        builder.append(sign_header_str)
        builder.append("\n")
        builder.append(self.__payload_transform(payload))

        return "".join(builder)

    @staticmethod
    def __url_transform(url_str: str) -> str:
        """URL转换"""
        parsed_url = urlparse(url_str)
        relative_path = parsed_url.path
        if not relative_path.endswith("/"):
            relative_path += "/"
        return urllib.parse.quote(relative_path, encoding='utf-8')

    @staticmethod
    def __query_str_transform(params: Dict) -> str:
        """查询字符串转换"""
        if not params:
            return ""
        params = sorted(params.items(), key=lambda x: x[0])
        return urllib.parse.urlencode(params).replace("%3D", "=")

    def __payload_transform(self, payload: str) -> str:
        """负载转换"""
        if not payload:
            return self.__sha256_hex_upper(b"")

        payload_bytes = payload.encode("utf-8")
        byte_values = [struct.unpack('b', bytes([byte]))[0] for byte in payload_bytes]
        byte_values.sort()
        new_payload = bytearray()
        for byte_value in byte_values:
            new_payload.append(byte_value)
        new_payload = self.__remove_spaces(new_payload)
        return self.__sha256_hex_upper(new_payload)

    @staticmethod
    def __remove_spaces(b: bytearray) -> bytearray:
        """移除空格"""
        j = 0
        for i in range(len(b)):
            if b[i] != 32:  # 32是空格的ASCII码
                if i != j:
                    b[j] = b[i]
                j += 1
        return b[:j]

    @staticmethod
    def __hmac_sha256_hex(secret_key: str, data: str) -> str:
        """计算HMAC-SHA256"""
        mac = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        return binascii.hexlify(mac.digest()).decode('utf-8').upper()

    @staticmethod
    def __sha256_hex_upper(b: bytes) -> str:
        """计算SHA256哈希"""
        return binascii.hexlify(hashlib.sha256(b).digest()).decode('utf-8').upper()

    @staticmethod
    def __reverse_hex(auth_code: str) -> bytes:
        """反转十六进制"""
        return binascii.unhexlify(auth_code)

    @staticmethod
    def __aes_cbc_decrypt(cipher_text: str, key: bytes) -> str:
        """AES-CBC解密"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # 使用全零IV（与原始实现一致）
        iv = b'\x00' * 16  # AES block size is 16 bytes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(bytes.fromhex(cipher_text)) + decryptor.finalize()
        return decrypted_data.decode("utf-8").rstrip('\x00')


class SecurityIncidentAPI:
    """安全事件API客户端"""

    def __init__(self, base_url: str, auth_code: Optional[str] = None,
                 ak: Optional[str] = None, sk: Optional[str] = None,
                 verify_ssl: bool = False):
        """
        初始化API客户端

        Args:
            base_url: API基础URL
            auth_code: 联动码
            ak: Access Key
            sk: Secret Key
            verify_ssl: 是否验证SSL证书
        """
        self.base_url = base_url.rstrip('/')
        self.signature = Signature(auth_code=auth_code, ak=ak, sk=sk)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.api_endpoint = f"{self.base_url}/api/xdr/v1/incidents/list"

    def get_timestamp(self, days_ago: int = 7) -> int:
        """获取时间戳"""
        target_time = datetime.now() - timedelta(days=days_ago)
        return int(target_time.timestamp())

    def get_incidents(self,
                     start_timestamp: Optional[int] = None,
                     end_timestamp: Optional[int] = None,
                     page_size: int = 5,
                     page: int = 1,
                     severities: Optional[List[int]] = None,
                     deal_status: Optional[List[int]] = None,
                     time_field: str = "endTime",
                     sort: str = "endTime:desc,severity:desc") -> Dict:
        """
        获取安全事件列表

        Args:
            start_timestamp: 起始时间戳
            end_timestamp: 结束时间戳
            page_size: 每页大小(5-200)
            page: 页码
            severities: 安全等级[0:信息,1:低危,2:中危,3:高危,4:严重]
            deal_status: 处置状态[0:未处置,10:处置中,40:已处置,50:已挂起,60:接受风险,70:已遏制]
            time_field: 时间字段
            sort: 排序规则

        Returns:
            API响应数据
        """
        # 设置默认时间范围
        if start_timestamp is None:
            start_timestamp = self.get_timestamp(7)
        if end_timestamp is None:
            end_timestamp = int(datetime.now().replace(hour=23, minute=59, second=59).timestamp())

        # 构建请求参数
        params = {
            "startTimestamp": start_timestamp,
            "endTimestamp": end_timestamp,
            "timeField": time_field,
            "pageSize": page_size,
            "page": page,
            "sort": sort
        }

        # 可选参数
        if severities:
            params["severities"] = severities
        if deal_status:
            params["dealStatus"] = deal_status

        # 构造请求
        headers = {
            "content-type": "application/json"
        }

        req = requests.Request("POST", self.api_endpoint,
                             headers=headers, data=json.dumps(params))

        # 签名
        self.signature.signature(req)

        try:
            response = self.session.send(req.prepare())
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"请求失败: {e}")
            return {}

    def format_incident(self, incident: Dict) -> str:
        """格式化单个安全事件信息"""
        severity_map = {
            -1: "信息",
            1: "低危",
            2: "中危",
            3: "高危",
            4: "严重"
        }

        deal_status_map = {
            0: "未处置",
            10: "处置中",
            40: "已处置",
            50: "已挂起",
            60: "接受风险",
            70: "已遏制"
        }

        severity = severity_map.get(incident.get("incidentSeverity", -1), "未知")
        deal_status = deal_status_map.get(incident.get("dealStatus", 0), "未知")

        start_time = datetime.fromtimestamp(incident.get("startTime", 0))
        end_time = datetime.fromtimestamp(incident.get("endTime", 0))

        return f"""
事件名称: {incident.get('name', 'N/A')}
事件ID: {incident.get('uuId', 'N/A')}
严重等级: {severity}
主机IP: {incident.get('hostIp', 'N/A')}
发生时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')} - {end_time.strftime('%Y-%m-%d %H:%M:%S')}
处置状态: {deal_status}
处置动作: {incident.get('dealAction', 'N/A')}
描述: {incident.get('description', 'N/A')}
威胁定性: {', '.join(incident.get('threatDefineName', []))}
风险标签: {', '.join(incident.get('riskTag', []))}
数据源: {', '.join(incident.get('dataSource', []))}
{'='*60}
"""

    def print_incidents(self, data: Dict):
        """打印安全事件列表"""
        if not data or data.get("code") != "Success":
            print(f"请求失败: {data.get('message', '未知错误')}")
            return

        incidents_data = data.get("data", {})
        total = incidents_data.get("total", 0)
        page = incidents_data.get("page", 1)
        page_size = incidents_data.get("pageSize", 5)
        items = incidents_data.get("item", [])

        print(f"""
安全事件列表查询结果:
总事件数: {total}
当前页码: {page}/{max(1, (total + page_size - 1) // page_size)}
本页事件数: {len(items)}
{'='*80}
""")

        for i, incident in enumerate(items, 1):
            print(f"事件 #{i}:")
            print(self.format_incident(incident))


def main():
    """主函数 - 使用示例"""
    # 配置API信息（使用提供的IP地址和联动码）
    BASE_URL = "https://10.5.41.194"  # 使用提供的IP地址

    # 认证方式选择（二选一）

    # 方式1: 使用联动码认证
    AUTH_CODE = "61653431636431352D643165372D346434302D393164662D6138336632376266373863667C7C7C73616E67666F727C76317C3132372E302E302E317C7C7C7C42384339313332383934313346413533444236443531443538384338313131324335454239433937323943433232343035334436443443324231384644354242433838394335333845353230454330443037363331334443393333364339373533454336353444414537313131433939354138324431313842463937363644367C42464646444531373135314535394539424332303433434334344441304345364543423042443833414130334336434236323935393445383745423937454442374236303341384637343438424442353936464343364238324237354531343343373636453832434432393744333436323832343936443734453442313442347C7C307C"  # 使用提供的联动码

    # 方式2: 直接使用AK/SK认证（注释掉上面的AUTH_CODE，取消下面的注释）
    # AK = "your_access_key_here"
    # SK = "your_secret_key_here"

    # 创建API客户端
    api_client = SecurityIncidentAPI(
        base_url=BASE_URL,
        auth_code=AUTH_CODE,  # 使用联动码
        # ak=AK, sk=SK,  # 或者使用AK/SK
        verify_ssl=False  # 生产环境建议设为True
    )

    print("=== 安全事件查询示例 ===\n")

    # 示例1: 获取最近7天的所有安全事件
    print("1. 获取最近7天的安全事件...")
    data = api_client.get_incidents(
        page_size=10,
        page=1
    )
    api_client.print_incidents(data)

    # 示例2: 获取高危和中危事件
    print("\n2. 获取高危和中危事件...")
    data = api_client.get_incidents(
        severities=[2, 3],  # 中危和高危
        page_size=5,
        page=1
    )
    api_client.print_incidents(data)

    # 示例3: 获取未处置的事件
    print("\n3. 获取未处置事件...")
    data = api_client.get_incidents(
        deal_status=[0],  # 未处置
        page_size=5,
        page=1
    )
    api_client.print_incidents(data)

    # 示例4: 自定义时间范围
    print("\n4. 获取特定时间范围的事件...")
    start_time = int((datetime.now() - timedelta(days=30)).timestamp())  # 30天前
    end_time = int(datetime.now().timestamp())  # 当前时间

    data = api_client.get_incidents(
        start_timestamp=start_time,
        end_timestamp=end_time,
        page_size=5,
        page=1
    )
    api_client.print_incidents(data)


if __name__ == "__main__":
    main()