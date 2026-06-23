#ifndef __KSU_H_WEB_SU_PROMPT
#define __KSU_H_WEB_SU_PROMPT

#include <linux/compiler_types.h>
#include <linux/types.h>

struct pt_regs;

void ksu_web_su_prompt_init(void);
void ksu_web_su_prompt_exit(void);

int ksu_install_su_request_fd(void);
int ksu_respond_su_request(u64 request_id, bool allow);

bool ksu_web_su_prompt_is_enabled(void);
bool ksu_web_su_prompt_ask(const char *path, const char __user *const __user *argv_user);

#endif // __KSU_H_WEB_SU_PROMPT
