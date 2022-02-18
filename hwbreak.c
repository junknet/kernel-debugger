#include "asm/current.h"
#include "asm/uaccess.h"
#include "linux/hw_breakpoint.h"
#include "linux/mmzone.h"
#include "linux/perf_event.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/types.h"
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
//开始阴间操作

typedef unsigned long (*lookup_name_t)(const char *name);
typedef int (*access_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

struct perf_event *sample_hbp;
struct perf_event *watch_hbp;
struct perf_event_attr attr;
static access_vm access_vm_fn;
static uint64_t soul_pid = 2644;
static uint64_t soul_base = 0xd3143000;

static void watch_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    // struct file *file;
    // unsigned char buff[10] = {0};
    // buff[0] = 'E';
    // buff[1] = 'L';
    // buff[2] = 'F';
    // file = filp_open("/data/local/tmp/dump.kernel", O_RDWR | O_CREAT, 0644);
    // kernel_write(file, buff, 10, 0);
    // filp_close(file, NULL);
    unregister_hw_breakpoint(watch_hbp);
}

static void sample_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{

    unregister_hw_breakpoint(sample_hbp);
    ptrace_breakpoint_init(&attr);
    attr.bp_addr = regs->regs[0];
    attr.bp_len = HW_BREAKPOINT_LEN_1;
    attr.bp_type = HW_BREAKPOINT_R;
    attr.disabled = 0;
    watch_hbp = register_user_hw_breakpoint(&attr, watch_handler, NULL, current);
}

static int __init main_init(void)
{

    struct task_struct *task = NULL;
    struct pid *proc_pid_struct = NULL;
    struct perf_event_attr attr;
    lookup_name_t lookup_name_fn;
    register_kprobe(&kp);
    lookup_name_fn = (lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    access_vm_fn = (access_vm)lookup_name_fn("access_process_vm");

    proc_pid_struct = find_get_pid(soul_pid);
    if (proc_pid_struct == NULL)
    {
        return -EINVAL;
    }
    task = get_pid_task(proc_pid_struct, PIDTYPE_PID);
    printk("pid:%d\n", task->pid);
    if (!task)
    {
        printk(KERN_INFO "get_pid_task failed.\n");
        return -EINVAL;
    }
    ptrace_breakpoint_init(&attr);
    attr.bp_addr = soul_base + 0x91c4c;
    attr.bp_len = HW_BREAKPOINT_LEN_2;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.disabled = 0;
    sample_hbp = register_user_hw_breakpoint(&attr, sample_hbp_handler, NULL, task);
    put_task_struct(task);
    return 0;
}

static void __exit main_exit(void)
{
    unregister_hw_breakpoint(sample_hbp);
}

module_init(main_init);
module_exit(main_exit);
MODULE_LICENSE("GPL");