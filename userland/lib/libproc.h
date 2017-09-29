#ifndef	__LIB_PROC__
#define __LIB_PROC__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#define __MAIN__	0


pthread_mutex_t proc_mutex = PTHREAD_MUTEX_INITIALIZER; /* 静态初始化 全局互斥锁 */

typedef struct {
	pthread_t		tid;	/* TID */
	pthread_attr_t		pattr;	/* 属性 */
	pthread_mutex_t		mutex;	/* 互斥锁 */
	pthread_mutexattr_t	mattr;	/* 互斥锁 属性 */
} PROC;


PROC *proc_init()
{
	PROC *p = NULL;

	if (!(p = (PROC *) calloc(1, sizeof(PROC)))) {
		perror("proc malloc error");
		goto PROC_INIT_ERR;
	}

	pthread_attr_init(&p->pattr);
	pthread_mutexattr_init(&p->mattr);

	if (pthread_mutexattr_setpshared(&p->mattr, PTHREAD_PROCESS_PRIVATE) != 0) {
		perror("proc mattr shared error");
		goto PROC_INIT_ERR;
	}

	if (pthread_mutexattr_settype(&p->mattr, PTHREAD_MUTEX_RECURSIVE) != 0) {
		perror("proc mattr settype error");
		goto PROC_INIT_ERR;
	}

	if (pthread_mutex_init(&p->mutex, &p->mattr) != 0) {
		perror("proc mutex init error");
		goto PROC_INIT_ERR;
	}

	if (pthread_attr_setdetachstate(&p->pattr, PTHREAD_CREATE_DETACHED) != 0) { /* 线程与用户分离 */
		perror("proc set detach error");
		goto PROC_INIT_ERR;
	}

	return p;

PROC_INIT_ERR:
	if (p) { free(p); }
	return NULL;
}

void proc_delete(PROC **p)
{
	if (p && *p) {
		if (pthread_mutex_destroy(&(*p)->mutex) != 0) {
			perror("proc mutex destroy error");
		}

		if (pthread_mutexattr_destroy(&(*p)->mattr) != 0) {
			perror("proc mattr destroy error");
		}

		if (pthread_attr_destroy(&(*p)->pattr) != 0) {
			perror("proc attr destroy error");
		}
		free(*p);
		*p = NULL;
	}
	return;
}

int proc_lock(PROC *p, const int wait)
{
	if (!p) { return -1; }
	if (wait) { return pthread_mutex_lock(&p->mutex); }
	return pthread_mutex_trylock(&p->mutex);
}

int proc_unlock(PROC *p)
{
	if (!p) { return -1; }
	return pthread_mutex_unlock(&p->mutex);
}

int proc_terminate(PROC *p)
{
	return pthread_kill(p->tid, SIGTERM);
}

int proc_kill(PROC *p)
{
	return pthread_kill(p->tid, SIGKILL);
}

int proc_wait(PROC *p)
{
	return pthread_join(p->tid, NULL);
}

int proc_start(PROC *p, void *func, void *arg)
{
	return pthread_create(&p->tid, &p->pattr, func, arg);
}

int proc_stop(PROC *p, const int timeout)
{
	if (p) {
		pthread_kill(p->tid, SIGTERM);
		sleep(timeout);
		pthread_kill(p->tid, SIGKILL);
		return pthread_join(p->tid, NULL);
	}
	return -1;
}


#if __MAIN__
static struct HANDLE {
	int num;
	PROC *p;
} handle = {0, NULL};


static void *sypply(void *param)
{
	int i = 0;

	for (i = 10; i < 20; i++) {
		proc_lock(handle.p, 1);
		handle.num = i;
		printf("proc(%ld): %d\n", handle.p->tid, handle.num);
		proc_unlock(handle.p);
		sleep(1);
	}

	// pthread_exit((void *) NULL);
	return (void *) NULL;
}

int main(void)
{
	int i = 0;

	if (!(handle.p = proc_init())) { return -1; }

	if (proc_start(handle.p, sypply, NULL) != 0) {
		proc_delete(&handle.p);
		return -1;
	}

	for (i = 0; i < 10; i++) {
		proc_lock(handle.p, 1);
		handle.num = i;
		printf("main(%ld): %d\n", pthread_self(), handle.num);
		proc_unlock(handle.p);
		sleep(1);
	}

	proc_stop(handle.p, 0);
	proc_delete(&handle.p);

	return 0;
}
#endif

#endif
