---
abbrlink: ''
categories:
- - 后门利用
date: '2026-11-04T15:14:28.180275+08:00'
tags:
- ebpf
title: eBPF 学习
updated: '2026-11-04T18:02:02.129+08:00'
---
```
## eBPF 是什么
eBPF(扩展的 Berkeley Packet Filter) 是一个允许开发者在不加载新模块，不修改内核源代码的情况下，在内核空间中运行小型程序的突破性技术。它有一下特点：
1. 在真正运行程序前会经过验证器检查其逻辑，防止错误代码导致内核崩溃。
2. 使用即时编译器 JIT，通过将字节码转换成对应优化后的机器码，实现接近原生的速度。
3. 直接与内核交互。

eBPF 广泛应用在安全审计，数据包处理和性能监控等高性能需求的场景下。

推荐个项目：[bpftime：向可观测性、网络、GPU 和通用扩展的用户空间 eBPF 运行时框架](https://github.com/eunomia-bpf/bpftime)

这个项目能够让系统在内核 eBPF 不可用的情况下（例如在较旧的操作系统或替代操作系统上，或者内核级权限受到限制的情况下），无需更改工具即可启用。

## eBPF 开发工具
* BCC：一个基于 Python 的工具链，简化了 eBPF 程序的编写、编译和加载。它提供了许多预构建的追踪工具，但在依赖和兼容性方面存在一些限制。
eBPF Go 库：一个 Go 库，解耦了获取 eBPF 字节码的过程与加载和管理 eBPF 程序的过程。
* libbpf-bootstrap：基于 libbpf 的现代脚手架，提供了高效的工作流用于编写 eBPF 程序，提供简单的一次性编译过程以生成可重用的字节码。
* eunomia-bpf：一个用于编写仅包含内核空间代码的 eBPF 程序的工具链。它通过动态加载 eBPF 程序简化了 eBPF 程序的开发。

## 课程示例

[bcc Python 开发者教程](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md    )

第五课.sync_count.py

要求：修改 sync_timing.py 程序（上一课已讲解），使其存储所有内核同步系统调用（包括快调用和慢调用）的次数，并将其与输出一起打印出来。可以通过向现有哈希表添加新的键索引，将此计数记录到 BPF 程序中。

```python
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    u64 count_fast, count_slow = 0;
    u64 count, count_key = 0;
    u64 count_p;
  
    crst = last.lookup(&count_key);

    if(crst != NULL){

    } else {
        count = 1;
    }
    last.update(&count_key, &count)

  
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("totle=%d, delta=%d\\n", count, delta / 1000000);
        } else {
            bpf_trace_printk("totle=%d\\n", count);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    except KeyboardInterrupt:
        exit()
```

```

```
