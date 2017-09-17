#include <linux/kern_levels.h>
#include <linux/printk.h>

#include <linux/slab.h>
#include <linux/gfp.h>

#include "stack.h"

stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t* new_entry = 
        (stack_entry_t*) kmalloc(sizeof(stack_entry_t), GFP_KERNEL);

    INIT_LIST_HEAD(&(new_entry->lh));
    STACK_ENTRY_DATA_RESET(new_entry, data);

    return new_entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    list_del(&(entry->lh));
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&(entry->lh), stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    if (stack_empty(stack)) {
        printk(KERN_WARNING "Attempt to pop from empty stack\n");
        return NULL;
    }

    stack_entry_t* prev_head = 
        list_entry(stack->next, stack_entry_t, lh);
    list_del_init(&(prev_head->lh));

    return prev_head;
}
