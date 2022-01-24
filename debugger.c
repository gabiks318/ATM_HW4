#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include "elf64.h"
#include "find_symbol.h"

void debugger(pid_t pid, unsigned long address)
{
    int wait_status;
    struct user_regs_struct regs;
    waitpid(pid, &wait_status, 0);

    // Insert breakpoint
    unsigned long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)address, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, pid, (void*)address , (void*)data_trap);

    // Continue execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &wait_status, 0);

    // Loop for each function execution
    while (WIFSTOPPED(wait_status))
    {
        // Restore original code
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, pid, (void *)address, (void *)data);

        // Insert breakpoint to return address
        Elf64_Addr return_address = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, NULL);
        unsigned long return_address_data = ptrace(PTRACE_PEEKTEXT, pid, return_address, NULL);
        unsigned long return_address_data_trap = (return_address_data & 0xFFFFFFFFFFFFFF00) | 0xCC;

        ptrace(PTRACE_POKETEXT, pid, return_address, (void *)return_address_data_trap);

        while (WIFSTOPPED(wait_status))
        {
            // Wait for syscall
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&wait_status);

            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            if (regs.rip == return_address + 1)
            {
                // Function finished
                ptrace(PTRACE_POKETEXT, pid, (void *)return_address, (void *)return_address_data);
                regs.rip -= 1;
                ptrace(PTRACE_SETREGS, pid, 0, &regs);

                // Insert breakpoint to fucntion in case of another call
                ptrace(PTRACE_POKETEXT, pid, (void *)address, (void *)data_trap);
                break;
            }

            unsigned long long syscall_address = regs.rip - 2;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, pid, 0, &regs);

            if ((int)(regs.rax) < 0)
            {
                printf("PRF:: the syscall in 0x%llx returned with %lld\n", syscall_address, regs.rax);
            }
        }

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, pid, 0, &regs);

        if (regs.rip - 1 == address)
        {
            continue;
        }

        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;
    }
}

pid_t run_target(const char *exec_file, char **argv)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        execl(exec_file, *(argv + 2), NULL);
    }
    else
    {
        if (pid < 0)
        {
            perror("fork");
            exit(1);
        }
        return pid;
    }
}

int main(int argc, char **argv)
{

    char *symbol_name = argv[1];
    char *exec_name = argv[2];

    unsigned int count = 0;
    long address = find_symbol(symbol_name, exec_name, &count);
    if (address == NOT_EXECUTABLE)
    {
        printf("PRF:: %s not an executable!\n", symbol_name);
        return 0;
    }

    if (address == NOT_FOUND)
    {
        printf("PRF:: %s not found!\n", symbol_name);
        return 0;
    }

    if (address == LOCAL_SYMBOL)
    {
        printf("PRF:: %s is a local symbol %d times!\n", symbol_name, count);
        return 0;
    }

    pid_t child = run_target(exec_name, argv);
    debugger(child, address);
    return 0;
}