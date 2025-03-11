#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* 64 KB in bytes */
#define BREAK_SIZE 65536
#define ALIGNMENT_SIZE 16

void *program_break_start = NULL;
void *program_break_end = NULL;

/* Header structure */
typedef struct Header
{
    size_t datasize;
    bool is_free;
    struct Header *next;
} Header;

/* Aligns size to next 16 byte increment */
size_t align_size(size_t size)
{
    return (size + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1);
}
/* Aligns pointer to next 16 byte increment */
uintptr_t align_ptr(uintptr_t ptr)
{
    return (ptr + ALIGNMENT_SIZE - 1) & ~(ALIGNMENT_SIZE - 1);
}

void *malloc(size_t size)
{
    int aligned_size = align_size(size);

    /* Base Case */
    if (aligned_size == 0)
    {
        return NULL;
    }

    /* Integer Overflow size */
    if (aligned_size < size)
    {
        errno = ENOMEM;
        return NULL;
    }

    /* We need to initialize program break and header */
    if (program_break_start == NULL)
    {
        /* Align program break */
        uintptr_t program_break = (uintptr_t)(0);
        uintptr_t aligned_program_break = align_ptr(program_break);
        uintptr_t skipped_bytes = aligned_program_break - program_break;

        if (skipped_bytes > 0)
        {
            if ((skipped_bytes) == (void *)-1)
            {
                errno = ENOMEM;
                return NULL;
            }
        }

        program_break_start = (BREAK_SIZE);
        if (program_break_start == (void *)-1)
        {
            errno = ENOMEM;
            return NULL;
        }
        program_break_end = (void *)((uintptr_t)
                                         program_break_start +
                                     BREAK_SIZE);
        Header *initial_header = (Header *)program_break_start;
        initial_header->datasize = BREAK_SIZE - align_size(sizeof(Header));
        initial_header->is_free = true;
        initial_header->next = NULL;
    }

    /* Visit headers until we find a suitable one */
    Header *current_header = (Header *)program_break_start;
    Header *prev_header = NULL;
    while (current_header != NULL)
    {
        if (current_header->is_free &&
            current_header->datasize >= aligned_size)
        {
            /* Found a suitable header */
            current_header->is_free = false;
            /* Chunk is larger than required */
            if (current_header->datasize > aligned_size +
                                               align_size(sizeof(Header)))
            {
                /* Create a new header after block and reroute linking */
                Header *new_header = (Header *)((uintptr_t)current_header +
                                                align_size(sizeof(Header)) +
                                                aligned_size);

                new_header->datasize = current_header->datasize - aligned_size -
                                       align_size(sizeof(Header));
                new_header->is_free = true;
                new_header->next = current_header->next;
                current_header->datasize = aligned_size;
                current_header->next = new_header;
            }
            /* return the address */
            void *return_address = (void *)((uintptr_t)current_header +
                                            align_size(sizeof(Header)));
            return return_address;
        }
        prev_header = current_header;
        current_header = current_header->next;
    }

    /* Could not find a suitable block for memory requested */
    void *old_program_break_end = (BREAK_SIZE);
    if (old_program_break_end == (void *)-1)
    {
        errno = ENOMEM;
        return NULL;
    }
    program_break_end = (void *)((uintptr_t)old_program_break_end + BREAK_SIZE);

    Header *new_header = (Header *)old_program_break_end;
    new_header->datasize = BREAK_SIZE - align_size(sizeof(Header));
    new_header->is_free = true;
    new_header->next = NULL;

    if (prev_header != NULL)
    {
        prev_header->next = new_header;
    }

    /* Expand newly created header until it fits requested space */
    while (new_header->datasize < aligned_size)
    {
        void *old_program_break_end = (BREAK_SIZE);
        if (old_program_break_end == (void *)-1)
        {
            errno = ENOMEM;
            return NULL;
        }
        program_break_end = (void *)((uintptr_t)
                                         old_program_break_end +
                                     BREAK_SIZE);
        new_header->datasize += BREAK_SIZE;
    }
    return malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total_size = nmemb * size;
    /* Base Case */
    if (nmemb == 0 || size == 0)
    {
        return NULL;
    }
    /* Account for Integer overflow */
    if (total_size / size != nmemb)
    {
        return NULL;
    }
    /* Allocate space and set to zero */
    void *mem_loc = malloc(total_size);
    if (mem_loc == NULL)
    {
        return NULL;
    }
    memset(mem_loc, 0, total_size);
    return mem_loc;
}

void *realloc(void *ptr, size_t size)
{
    /* Base Cases */
    if (ptr == NULL)
    {
        void *new_mem_ptr = malloc(size);
        return new_mem_ptr;
    }
    if (size == 0)
    {
        free(ptr);
        return NULL;
    }
    /* Find header */
    Header *header = (Header *)((uintptr_t)ptr - align_size(sizeof(Header)));
    size_t aligned_size = align_size(size);

    /* Current header can fit realloc memory */
    if (header->datasize >= aligned_size)
    {
        /* Have extra space after */
        if (header->datasize > aligned_size + align_size(sizeof(Header)))
        {
            /* Create a new header after memory block */
            Header *new_header = (Header *)((uintptr_t)header +
                                            align_size(sizeof(Header)) +
                                            aligned_size);
            new_header->datasize = header->datasize - aligned_size -
                                   align_size(sizeof(Header));
            new_header->is_free = true;
            new_header->next = header->next;
            header->datasize = aligned_size;
            header->next = new_header;
        }
        return ptr;
    }
    /*
        Current header is not enough
        Attempt to merge with next header
    */
    Header *next_header = header->next;
    if (next_header != NULL && next_header->is_free)
    {
        size_t combined_size = header->datasize + align_size(sizeof(Header)) +
                               next_header->datasize;
        if (combined_size >= aligned_size)
        {
            header->datasize = combined_size;
            header->next = next_header->next;
            return ptr;
        }
    }
    /* Have to find a new spot for memory */
    void *new_mem_ptr = malloc(size);
    if (new_mem_ptr == NULL)
    {
        return NULL;
    }
    memcpy(new_mem_ptr, ptr,
           aligned_size < header->datasize ? aligned_size : header->datasize);
    free(ptr);
    return new_mem_ptr;
}

void free(void *ptr)
{
    /* ptr is outside of bounds */
    if (ptr == NULL ||
        ptr < program_break_start + align_size(sizeof(Header)) ||
        ptr >= program_break_end)
    {
        return;
    }
    /* Check for valid pointer 16 byte alignment */
    if ((uintptr_t)ptr % ALIGNMENT_SIZE != 0)
    {
        return;
    }
    /* Find Header */
    Header *header = (Header *)program_break_start;
    Header *prev_header = NULL;
    while (((uintptr_t)ptr > ((uintptr_t)header +
                              align_size(sizeof(Header)))) &&
           ((uintptr_t)ptr < ((uintptr_t)header +
                              align_size(sizeof(Header)) +
                              header->datasize)))
    {
        prev_header = header;
        header = header->next;
    }
    header->is_free = true;
    /* Attempt to merge with next block */
    while (header->next != NULL && header->next->is_free)
    {
        header->datasize += sizeof(Header) + header->next->datasize;
        header->next = header->next->next;
    }
    /* Attempt to merge with previous block */
    if (prev_header != NULL && prev_header->is_free)
    {
        prev_header->datasize += sizeof(Header) + header->datasize;
        prev_header->next = header->next;
    }

    return;
}
