/*
 * examples/seh_demo.c -- minimal repro for the "SEH/exception interaction"
 * todo item (look/todo.md, section D): does an exception raised deep inside
 * a *virtualized* call chain still reach the OS's own structured-exception
 * dispatch (frame-by-frame unwind via RtlVirtualUnwind) all the way up to a
 * top-level handler, instead of the walk derailing partway through injected
 * code with no RUNTIME_FUNCTION/UNWIND_INFO entry?
 *
 * boom() dereferences a null pointer -- a genuine hardware access
 * violation -- from inside a real, direct (same-module) call made by
 * main() itself, which is the --entry target (its own call-to-boom is part
 * of what gets lifted into the virtualized region).
 *
 * Expected (both unprotected and correctly protected): the access violation
 * reaches top_level_filter, which prints "caught" and exits 42. See
 * look/todo.md for the current, honest status of this demo against a real
 * protected binary (the vm_thunk/native_call/interpreter unwind info itself
 * is verified correct; a separate, newly-discovered nanomite interaction
 * still blocks this exact demo end-to-end and is tracked separately).
 */
#include <stdio.h>
#include <windows.h>

__attribute__((noinline)) int boom(int x)
{
    volatile int *p = (int *)(long long)x;
    return *p;
}

static LONG WINAPI top_level_filter(EXCEPTION_POINTERS *info)
{
    (void)info;
    printf("caught\n");
    fflush(stdout);
    ExitProcess(42);
}

int main(void)
{
    SetUnhandledExceptionFilter(top_level_filter);
    int result = boom(0);
    printf("result=%d\n", result); /* never reached -- boom() always faults */
    return 1;
}
