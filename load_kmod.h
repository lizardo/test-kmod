#ifndef LOAD_KMOD_H
#define LOAD_KMOD_H

void load_module(const char *path);
int (*init_module)();
void (*cleanup_module)();

#endif
