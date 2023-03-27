#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstring>
#include <pwd.h>
#include <cstdio>


void signal_handler(int sig, siginfo_t *siginfo, void *context)
{
    std::cout << "Received a SIGUSR1 signal from process " << siginfo->si_pid << " executed by ";
    
    struct passwd *pwd;
    pwd = getpwuid(siginfo->si_uid);
    
    if (pwd == nullptr)
    {
        std::cout << "unknown user" << std::endl;
    }
    else
    {
        std::cout << pwd->pw_name << " (" << siginfo->si_uid << ")" << std::endl;
    }

    ucontext_t *ucontext = (ucontext_t *)context;
    printf("State of the context: RIP = 0x%llx, RAX = 0x%llx, RBX = 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RIP], ucontext->uc_mcontext.gregs[REG_RAX], ucontext->uc_mcontext.gregs[REG_RBX]);
}

int main()
{
    std::cout << "My PID is " << getpid() << std::endl;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGUSR1, &sa, nullptr) != 0)
    {
        std::cerr << "Error" << std::endl;
        return 1;
    }

    while (true)
    {
        sleep(10);
    }

    return 0;
}
