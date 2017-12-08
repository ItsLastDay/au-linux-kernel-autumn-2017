#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <mutex.h>

#define TEST(TESTion) \
    if (!(TESTion)) { \
        fprintf(stderr, "%s %d\n", __FILE__, __LINE__); \
        perror("Test failed"); \
        abort(); \
    }

void* test_lock_mutex_ok(void *vmutex)
{
    mutex_t *mutex = (mutex_t*)vmutex;
    TEST(mutex_lock(mutex) == MUTEX_OK);
    return NULL;
}

void* test_lock_mutex_nok(void *vmutex)
{
    mutex_t *mutex = (mutex_t*)vmutex;
    TEST(mutex_lock(mutex) != MUTEX_OK);
    return NULL;
}

void test_once()
{
    TEST(mutex_lib_init() == MUTEX_OK);
    TEST(mutex_lib_init() != MUTEX_OK);
    mutex_t mutex1;
    mutex_t mutex2;
    mutex_t mutex3;
    mutex_t mutex4;
    mutex_t mutex5;

    TEST(mutex_init(&mutex1) == MUTEX_OK);
    TEST(mutex_init(&mutex2) == MUTEX_OK);
    TEST(mutex_init(&mutex3) == MUTEX_OK);
    TEST(mutex_init(&mutex4) == MUTEX_OK);
    TEST(mutex_init(&mutex5) == MUTEX_OK);

    TEST(mutex_lock(&mutex1) == MUTEX_OK);
    TEST(mutex_lock(&mutex2) == MUTEX_OK);
    TEST(mutex_lock(&mutex3) == MUTEX_OK);
    TEST(mutex_lock(&mutex4) == MUTEX_OK);
    TEST(mutex_lock(&mutex5) == MUTEX_OK);

    pthread_attr_t thread_attrs;
    pthread_attr_init(&thread_attrs);
    pthread_t thread;
    pthread_create(&thread, &thread_attrs, test_lock_mutex_ok, &mutex4);
    usleep(2 * 1000 * 1000); // 2 secs
    TEST(mutex_unlock(&mutex4) == MUTEX_OK);
    pthread_join(thread, NULL);

    TEST(mutex_unlock(&mutex1) == MUTEX_OK);
    TEST(mutex_unlock(&mutex2) == MUTEX_OK);
    TEST(mutex_unlock(&mutex3) == MUTEX_OK);
    TEST(mutex_unlock(&mutex5) == MUTEX_OK);

    // Check mutex destruction while it is locked and another
    // thread is waiting its locking
    TEST(mutex_lock(&mutex5) == MUTEX_OK);
    pthread_create(&thread, &thread_attrs, test_lock_mutex_nok, &mutex5);
    usleep(2 * 1000 * 1000); // 2 secs
    TEST(mutex_deinit(&mutex5) == MUTEX_OK);
    pthread_join(thread, NULL); // waiter should be woken up with error returned

    // Check that everything is ok after destruction of
    // process mutex context
    TEST(mutex_lib_deinit() == MUTEX_OK);

    // When all the internal mutex spinlocks
    // are unlocked we do the fast path here
    // no validation is performed. So returns OK.
    TEST(mutex_lock(&mutex1) == MUTEX_OK);
    TEST(mutex_lock(&mutex2) == MUTEX_OK);
    TEST(mutex_lock(&mutex3) == MUTEX_OK);
    TEST(mutex_lock(&mutex4) != MUTEX_OK);

    // Now all the mutexes are locked.
    // So we have slow path - full validation and wait in
    // the kernel. But.. library is not initialized.
    // So we should have error.
    TEST(mutex_lock(&mutex1) != MUTEX_OK);
    TEST(mutex_lock(&mutex2) != MUTEX_OK);
    TEST(mutex_lock(&mutex3) != MUTEX_OK);
    TEST(mutex_lock(&mutex4) != MUTEX_OK);

    pthread_create(&thread, &thread_attrs, test_lock_mutex_nok, &mutex1);
    pthread_join(thread, NULL);

    pthread_create(&thread, &thread_attrs, test_lock_mutex_nok, &mutex3);
    pthread_join(thread, NULL);

    // Fast path again
    TEST(mutex_unlock(&mutex1) == MUTEX_OK);
    TEST(mutex_unlock(&mutex2) == MUTEX_OK);
    TEST(mutex_unlock(&mutex3) == MUTEX_OK);
    TEST(mutex_unlock(&mutex4) == MUTEX_OK);
}

int main(void)
{
    test_once();
    test_once();
    return EXIT_SUCCESS;
}
