#include <stdint.h>
#include <stddef.h>
void *lanboat_apple_session(int port, const char *user, const char *password, int minimum, int maximum);
void lanboat_apple_start(void *session, uintptr_t handle, const char *url, const char *method, const char *headers, void *body, size_t length);
void lanboat_apple_cancel(void *session, uintptr_t handle);
void lanboat_apple_finish(void *session);
void lanboat_apple_retain(void *session);
void lanboat_apple_release(void *session);
char *lanboat_apple_network(void);
