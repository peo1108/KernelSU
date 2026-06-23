#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "feature/web_su_prompt.h"
#include "infra/event_queue.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/feature.h"
#include "uapi/ksu.h"

#define KSU_SU_REQUEST_TIMEOUT_MS 15000U
#define KSU_SU_REQUEST_MAX_QUEUED 64U

struct ksu_su_request_waiter {
    struct list_head list;
    u64 request_id;
    struct completion done;
    bool decided;
    bool allow;
};

static bool ksu_web_su_prompt_enabled;
static atomic64_t ksu_su_request_next_id = ATOMIC64_INIT(1);
static DEFINE_MUTEX(ksu_su_request_lock);
static LIST_HEAD(ksu_su_request_waiters);
static struct ksu_event_queue ksu_su_request_queue;
static DEFINE_MUTEX(ksu_su_request_fd_lock);
static bool ksu_su_request_fd_active;

static int web_su_prompt_feature_get(u64 *value)
{
    *value = ksu_web_su_prompt_enabled ? 1 : 0;
    return 0;
}

static int web_su_prompt_feature_set(u64 value)
{
    ksu_web_su_prompt_enabled = value != 0;
    pr_info("web_su_prompt: set to %d\n", ksu_web_su_prompt_enabled);
    return 0;
}

static const struct ksu_feature_handler web_su_prompt_handler = {
    .feature_id = KSU_FEATURE_WEB_SU_PROMPT,
    .name = "web_su_prompt",
    .get_handler = web_su_prompt_feature_get,
    .set_handler = web_su_prompt_feature_set,
};

bool ksu_web_su_prompt_is_enabled(void)
{
    return ksu_web_su_prompt_enabled;
}

static ssize_t ksu_su_request_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return ksu_event_queue_read(&ksu_su_request_queue, buf, count, file->f_flags);
}

static __poll_t ksu_su_request_poll(struct file *file, poll_table *wait)
{
    return ksu_event_queue_poll(&ksu_su_request_queue, file, wait);
}

static int ksu_su_request_release(struct inode *inode, struct file *file)
{
    mutex_lock(&ksu_su_request_fd_lock);
    ksu_su_request_fd_active = false;
    mutex_unlock(&ksu_su_request_fd_lock);

    pr_info("web_su_prompt: request fd released\n");
    return 0;
}

static const struct file_operations ksu_su_request_fops = {
    .owner = THIS_MODULE,
    .read = ksu_su_request_read,
    .poll = ksu_su_request_poll,
    .release = ksu_su_request_release,
    .llseek = noop_llseek,
};

int ksu_install_su_request_fd(void)
{
    struct file *filp;
    int fd;

    mutex_lock(&ksu_su_request_fd_lock);

    if (ksu_su_request_fd_active) {
        fd = -EBUSY;
        goto out_unlock;
    }

    if (READ_ONCE(ksu_su_request_queue.closed)) {
        fd = -EPIPE;
        goto out_unlock;
    }

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0)
        goto out_unlock;

    filp = anon_inode_getfile("[ksu_su_request]", &ksu_su_request_fops, NULL, O_RDONLY | O_CLOEXEC);
    if (IS_ERR(filp)) {
        put_unused_fd(fd);
        fd = PTR_ERR(filp);
        goto out_unlock;
    }

    ksu_su_request_fd_active = true;
    fd_install(fd, filp);
    pr_info("web_su_prompt: request fd installed %d for pid %d\n", fd, current->pid);

out_unlock:
    mutex_unlock(&ksu_su_request_fd_lock);
    return fd;
}

int ksu_respond_su_request(u64 request_id, bool allow)
{
    struct ksu_su_request_waiter *waiter;
    int ret = -ENOENT;

    mutex_lock(&ksu_su_request_lock);
    list_for_each_entry (waiter, &ksu_su_request_waiters, list) {
        if (waiter->request_id == request_id) {
            waiter->allow = allow;
            waiter->decided = true;
            complete(&waiter->done);
            ret = 0;
            break;
        }
    }
    mutex_unlock(&ksu_su_request_lock);

    return ret;
}

static void ksu_su_request_copy_argv(char *out, size_t out_len, const char __user *const __user *argv_user)
{
    const char __user *argp;
    size_t off = 0;
    int i;
    long copied;

    if (!out_len)
        return;

    out[0] = '\0';
    if (!argv_user)
        return;

    for (i = 0; i < 8 && off + 1 < out_len; i++) {
        if (get_user(argp, &argv_user[i]) || !argp)
            break;

        if (off) {
            out[off++] = ' ';
            if (off >= out_len)
                break;
        }

        copied = strncpy_from_user(out + off, argp, out_len - off);
        if (copied < 0) {
            out[off] = '\0';
            break;
        }

        if ((size_t)copied >= out_len - off) {
            out[out_len - 1] = '\0';
            break;
        }

        off += copied;
    }
}

bool ksu_web_su_prompt_ask(const char *path, const char __user *const __user *argv_user)
{
    struct ksu_su_request_waiter waiter;
    struct ksu_su_request_event event = {};
    long timeout;
    int ret;

    if (!ksu_web_su_prompt_enabled)
        return false;

    waiter.request_id = (u64)atomic64_inc_return(&ksu_su_request_next_id);
    init_completion(&waiter.done);
    waiter.decided = false;
    waiter.allow = false;

    event.version = KSU_SU_REQUEST_EVENT_VERSION;
    event.request_id = waiter.request_id;
    event.deadline_ms = jiffies_to_msecs(jiffies + msecs_to_jiffies(KSU_SU_REQUEST_TIMEOUT_MS));
    event.uid = current_uid().val;
    event.euid = current_euid().val;
    event.pid = task_pid_nr(current);
    event.tgid = task_tgid_nr(current);
    event.ppid = task_tgid_nr(current->real_parent);
    strscpy(event.comm, current->comm, sizeof(event.comm));
    strscpy(event.path, path, sizeof(event.path));
    ksu_su_request_copy_argv(event.argv, sizeof(event.argv), argv_user);

    mutex_lock(&ksu_su_request_lock);
    list_add_tail(&waiter.list, &ksu_su_request_waiters);
    mutex_unlock(&ksu_su_request_lock);

    ret = ksu_event_queue_push(&ksu_su_request_queue, 1, 0, &event, sizeof(event), GFP_KERNEL);
    if (ret) {
        pr_warn("web_su_prompt: failed to queue request %llu: %d\n", waiter.request_id, ret);
        goto out_remove;
    }

    timeout = wait_for_completion_interruptible_timeout(&waiter.done, msecs_to_jiffies(KSU_SU_REQUEST_TIMEOUT_MS));
    if (timeout <= 0) {
        pr_info("web_su_prompt: request %llu denied by timeout/interruption\n", waiter.request_id);
        waiter.allow = false;
    }

out_remove:
    mutex_lock(&ksu_su_request_lock);
    list_del(&waiter.list);
    mutex_unlock(&ksu_su_request_lock);

    return waiter.decided && waiter.allow;
}

void __init ksu_web_su_prompt_init(void)
{
    int ret;

    ksu_web_su_prompt_enabled = false;
    ksu_event_queue_init(&ksu_su_request_queue, KSU_SU_REQUEST_MAX_QUEUED, sizeof(struct ksu_su_request_event));

    mutex_lock(&ksu_su_request_fd_lock);
    ksu_su_request_fd_active = false;
    mutex_unlock(&ksu_su_request_fd_lock);

    ret = ksu_register_feature_handler(&web_su_prompt_handler);
    if (ret) {
        pr_err("web_su_prompt: failed to register feature handler: %d\n", ret);
    }
}

void __exit ksu_web_su_prompt_exit(void)
{
    struct ksu_su_request_waiter *waiter;

    ksu_unregister_feature_handler(KSU_FEATURE_WEB_SU_PROMPT);
    ksu_event_queue_close(&ksu_su_request_queue);

    mutex_lock(&ksu_su_request_lock);
    list_for_each_entry (waiter, &ksu_su_request_waiters, list) {
        waiter->allow = false;
        waiter->decided = true;
        complete(&waiter->done);
    }
    mutex_unlock(&ksu_su_request_lock);

    ksu_event_queue_destroy(&ksu_su_request_queue);
}
