#ifndef __KSU_PROCESS_TAG_H
#define __KSU_PROCESS_TAG_H

#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

enum process_tag_type {
    PROCESS_TAG_KSUD = 0, // ksud 进程
    PROCESS_TAG_APP = 1, // 提权的应用进程
    PROCESS_TAG_MODULE = 2, // 模块脚本进程
    PROCESS_TAG_MANAGER = 3, // 管理器进程
    PROCESS_TAG_NONE = 255, // 未标记
};

struct process_tag {
    enum process_tag_type type;
    char name[64]; // 模块名 / 包名 / 空字符串
    atomic_t refcount;
    struct rcu_head rcu;
};

// 添加或更新进程 tag
int ksu_process_tag_set(pid_t pid, enum process_tag_type type, const char *name);

// 查询进程 tag（返回带 refcount++ 的指针）
struct process_tag *ksu_process_tag_get(pid_t pid);

// 释放 tag 引用
void ksu_process_tag_put(struct process_tag *tag);

// 删除进程的 tag
void ksu_process_tag_delete(pid_t pid);

// 清空所有 tag
void ksu_process_tag_flush(void);

// 检查是否启用
bool ksu_process_tag_is_enabled(void);

// 初始化和清理
void ksu_process_tag_init(void);
void ksu_process_tag_exit(void);

#endif
