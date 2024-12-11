#pragma once

/**
 * This is a toolbox with common testing tools for streams.
 */

#include "yatest.h"
#include <dnscore/input_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/output_stream.h>
#include <signal.h>

union yatest_lo32hi32_u
{
    struct
    {
        uint32_t lo_u32;
        uint32_t hi_u32;
    };
    uint64_t value_u64;
    void    *value_ptr;
};

typedef union yatest_lo32hi32_u yatest_lo32hi32_t;

// note: there is always a LF after a '.'
static const char yatest_lorem_ipsum[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
    "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n"
    "Vestibulum sed arcu non odio euismod lacinia at.\n"
    "Mauris sit amet massa vitae tortor condimentum lacinia quis vel.\n"
    "Mattis enim ut tellus elementum sagittis vitae et leo duis.\n"
    "Sit amet consectetur adipiscing elit ut aliquam purus sit.\n"
    "Nisi porta lorem mollis aliquam.\n"
    "A erat nam at lectus urna duis.\n"
    "Consequat id porta nibh venenatis cras sed felis.\n"
    "Risus nullam eget felis eget nunc lobortis mattis aliquam faucibus.\n";

static ya_result yatest_random_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    uint8_t          *buffer = (uint8_t *)buffer_;
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t size = size_next.lo_u32;
    if(size == 0)
    {
        return 0;
    }
    uint32_t next = size_next.hi_u32;
    if(len > size)
    {
        len = size;
    }
    for(uint32_t i = 0; i < len; ++i)
    {
        next = next * 1103515245 + 12345;
        buffer[i] = (unsigned int)(next / 65536) % 32768;
    }
    size -= len;
    size_next.lo_u32 = size;
    size_next.hi_u32 = next;
    stream->data = size_next.value_ptr;
    return len;
}

static ya_result yatest_random_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t size = size_next.lo_u32;
    if(size == 0)
    {
        return 0;
    }
    uint32_t next = size_next.hi_u32;
    if(len > size)
    {
        len = size;
    }
    for(uint32_t i = 0; i < len; ++i)
    {
        next = next * 1103515245 + 12345;
    }
    size -= len;
    size_next.lo_u32 = size;
    size_next.hi_u32 = next;
    stream->data = size_next.value_ptr;
    return len;
}

static void yatest_random_input_stream_close(input_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = NULL;
}

static const input_stream_vtbl yatest_random_input_stream_vtbl = {yatest_random_input_stream_read, yatest_random_input_stream_skip, yatest_random_input_stream_close, "random_input_stream"};

void                           yatest_random_input_stream_init(input_stream_t *stream, uint32_t size)
{
    yatest_lo32hi32_t size_next;
    size_next.lo_u32 = size;
    size_next.hi_u32 = 0; // seed
    stream->data = size_next.value_ptr;
    stream->vtbl = &yatest_random_input_stream_vtbl;
}

static ya_result yatest_loremipsum_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    uint8_t *buffer = (uint8_t *)buffer_;
    intptr_t offset = (intptr_t)stream->data;
    intptr_t size = sizeof(yatest_lorem_ipsum) - 1 - offset; // -1 because we don't want the NUL terminator.
    if(size == 0)
    {
        return 0;
    }
    if(len > size)
    {
        len = size;
    }
    for(uint32_t i = 0; i < len; ++i)
    {
        buffer[i] = yatest_lorem_ipsum[offset + i];
    }
    offset += len;
    stream->data = (void *)offset;
    return len;
}

static ya_result yatest_loremipsum_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    intptr_t offset = (intptr_t)stream->data;
    intptr_t size = sizeof(yatest_lorem_ipsum) - 1 - offset; // -1 because we don't want the NUL terminator.
    if(size == 0)
    {
        return 0;
    }
    if(len > size)
    {
        len = size;
    }
    offset += len;
    stream->data = (void *)offset;
    return len;
}

static void yatest_loremipsum_input_stream_close(input_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = NULL;
}

static const input_stream_vtbl yatest_loremipsum_input_stream_vtbl = {yatest_loremipsum_input_stream_read, yatest_loremipsum_input_stream_skip, yatest_loremipsum_input_stream_close, "loremipsum_input_stream"};

void                           yatest_loremipsum_input_stream_init(input_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = &yatest_loremipsum_input_stream_vtbl;
}

static ya_result yatest_error_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    uint8_t          *buffer = (uint8_t *)buffer_;
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t countdown = size_next.lo_u32;
    uint32_t error = size_next.hi_u32;
    if(countdown == 0)
    {
        return (ya_result)error;
    }
    if(len > countdown)
    {
        len = countdown;
    }
    for(uint32_t i = 0; i < len; ++i)
    {
        buffer[i] = 1;
    }
    countdown -= len;
    size_next.lo_u32 = countdown;
    stream->data = size_next.value_ptr;
    return len;
}

static ya_result yatest_error_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t countdown = size_next.lo_u32;
    uint32_t error = size_next.hi_u32;
    if(countdown == 0)
    {
        return (ya_result)error;
    }
    if(len > countdown)
    {
        len = countdown;
    }
    countdown -= len;
    size_next.lo_u32 = countdown;
    stream->data = size_next.value_ptr;
    return len;
}

static void yatest_error_input_stream_close(input_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = NULL;
}

static const input_stream_vtbl yatest_error_input_stream_vtbl = {yatest_error_input_stream_read, yatest_error_input_stream_skip, yatest_error_input_stream_close, "error_input_stream"};

void                           yatest_error_input_stream_init(input_stream_t *stream, uint32_t countdown, uint32_t error_code)
{
    yatest_lo32hi32_t size_next;
    size_next.lo_u32 = countdown;
    size_next.hi_u32 = error_code;
    stream->data = size_next.value_ptr;
    stream->vtbl = &yatest_error_input_stream_vtbl;
}

static ya_result yatest_error_output_stream_write(output_stream_t *stream, const uint8_t *buffer_, uint32_t len)
{
    (void)buffer_;
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t countdown = size_next.lo_u32;
    uint32_t error = size_next.hi_u32;
    if(countdown == 0)
    {
        return (ya_result)error;
    }
    if(len > countdown)
    {
        len = countdown;
    }
    countdown -= len;
    size_next.lo_u32 = countdown;
    stream->data = size_next.value_ptr;
    return len;
}

static ya_result yatest_error_output_stream_flush(output_stream_t *stream)
{
    yatest_lo32hi32_t size_next;
    size_next.value_ptr = stream->data;
    uint32_t countdown = size_next.lo_u32;
    uint32_t error = size_next.hi_u32;
    if(countdown == 0)
    {
        return (ya_result)error;
    }

    return SUCCESS;
}

static void yatest_error_output_stream_close(output_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = NULL;
}

static const output_stream_vtbl yatest_error_output_stream_vtbl = {yatest_error_output_stream_write, yatest_error_output_stream_flush, yatest_error_output_stream_close, "error_input_stream"};

void                            yatest_error_output_stream_init(output_stream_t *stream, uint32_t countdown, uint32_t error_code)
{
    yatest_lo32hi32_t size_next;
    size_next.lo_u32 = countdown;
    size_next.hi_u32 = error_code;
    stream->data = size_next.value_ptr;
    stream->vtbl = &yatest_error_output_stream_vtbl;
}

/**
 * Must return an input stream with always the same content if its size was infinite.
 * What I mean is that whatever its size, the byte at position x will always have
 * the same value.
 */

typedef int yatest_input_stream_factory(input_stream_t *is, uint32_t *in_out_size);

/**
 * Values should always be 1 for the small read, 4K+1 for the big read and the increment should be 1.
 */
int yatest_input_stream_read_consistency_test(yatest_input_stream_factory *factory, uint32_t size, uint32_t small_read, uint32_t big_read, uint32_t increment, char *name)
{
    input_stream_t is;
    int            ret;
    char           dummy[1];

    // instantiate and read the steam

    uint32_t model_size = size;
    ret = factory(&is, &model_size);
    if(ret != 0)
    {
        yatest_err("yatest_input_stream_read_consistency_test: %s: failed to instantiate model", name);
        return ret;
    }

    char *model = (char *)malloc(model_size);
    ret = input_stream_read_fully(&is, model, model_size);
    if(ret != (int)model_size)
    {
        yatest_err("yatest_input_stream_read_consistency_test: %s: failed to read model: size=%u, real=%u, ret=%i/%08x", name, size, model_size, ret, ret);
        return ret;
    }

    ret = input_stream_read(&is, dummy, 0);
    if(ret != 0)
    {
        yatest_err("yatest_input_stream_read_consistency_test: %s: expected to read exacly 0 bytes, got %i/%08x", name, ret, ret);
        return ret;
    }

    input_stream_close(&is);

    // for all combinations, read that same stream and compare

    uint8_t *sample = (uint8_t *)malloc(model_size);

    for(uint32_t chunk_size = small_read; chunk_size <= big_read; chunk_size += increment)
    {
        // ensure the content is absolutely different from the expectations
        for(uint32_t i = 0; i < model_size; ++i)
        {
            sample[i] = ~model[i];
        }

        uint32_t sample_size;
        sample_size = model_size;
        ret = factory(&is, &model_size);
        if(ret != 0)
        {
            yatest_err("yatest_input_stream_read_consistency_test: %s: failed to instantiate sample", name);
            return ret;
        }

        if(model_size != sample_size)
        {
            yatest_err(
                "yatest_input_stream_read_consistency_test: %s: failed to instantiate a sample of the right size: %u "
                "instead of %u",
                name,
                sample_size,
                model_size);
            input_stream_close(&is);
            return 1;
        }

        uint8_t       *p = sample;
        const uint8_t *limit = sample + sample_size;
        while(p < limit)
        {
            ret = input_stream_read(&is, p, chunk_size);
            if(ret <= 0)
            {
                yatest_err(
                    "yatest_input_stream_read_consistency_test: %s: unexpected error or EOF reading sample: %i instead "
                    "of %u",
                    name,
                    ret,
                    chunk_size);
                input_stream_close(&is);
                return 2;
            }
            p += ret;
        }

        ret = input_stream_read(&is, p, chunk_size);

        if(ret > 0)
        {
            yatest_err(
                "yatest_input_stream_read_consistency_test: %s: expected error or EOF reading sample: got %i=%08x "
                "instead (chunk_size=%u)",
                name,
                ret,
                read,
                chunk_size);
            return 1;
        }

        input_stream_close(&is);

        if(memcmp(model, sample, model_size) != 0)
        {
            yatest_err("yatest_input_stream_read_consistency_test: %s: model and sample differ for chunk size %u", name, chunk_size);
            return 3;
        }
    }

    free(sample);
    free(model);

    return 0;
}

/**
 * Must return an output stream with always the same capacity.
 */

typedef int yatest_output_stream_factory(output_stream_t *os, uint32_t *in_out_size);

/**
 * Returns the content of the output stream as an allocated buffer
 */

typedef int yatest_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep);

int         yatest_output_stream_write_consistency_test(yatest_output_stream_factory *factory, yatest_output_stream_close_readback *readback, uint32_t size, uint32_t small_write, uint32_t big_write, uint32_t increment, char *name)
{
    int             ret;
    input_stream_t  ris;
    output_stream_t os;
    uint32_t        model_size = size;
    ret = factory(&os, &model_size);
    if(ret != 0)
    {
        yatest_err("yatest_output_stream_write_consistency_test: %s: failed to instantiate model", name);
        return ret;
    }

    // make the content

    yatest_random_input_stream_init(&ris, model_size);
    uint8_t *random_array = (uint8_t *)malloc(model_size);
    input_stream_read_fully(&ris, random_array, model_size);

    // first write the whole block at once
    if((ret = output_stream_write(&os, &ret, 0)) != 0)
    {
        yatest_err("yatest_output_stream_write_consistency_test: %s: writing 0 bytes returned %i instead of 0", name, ret);
        return ret;
    }

    output_stream_write_fully(&os, random_array, model_size);
    uint8_t *stream_array;
    size_t   stream_array_size;
    ret = readback(&os, (void **)&stream_array, &stream_array_size);
    if(ret != 0)
    {
        yatest_err("yatest_output_stream_write_consistency_test: %s: failed to read-back model with %i/%08x", name, ret, ret);
        return ret;
    }

    if(stream_array_size != model_size)
    {
        yatest_err("yatest_output_stream_write_consistency_test: %s: model (%i) and read-back size (%i) differ", name, model_size, stream_array_size);
        return 1;
    }

    if(memcmp(stream_array, random_array, model_size) != 0)
    {
        yatest_err("yatest_output_stream_write_consistency_test: %s: model and read-back content differ for size %i", name, model_size);
        return 1;
    }

    free(stream_array);
    stream_array = NULL;
    stream_array_size = 0;

    for(int flushes = 0; flushes <= 1; ++flushes)
    {
        for(uint32_t chunk_size = small_write; chunk_size <= big_write; chunk_size += increment)
        {
            uint32_t sample_size = model_size;
            ret = factory(&os, &sample_size);
            if(FAIL(ret))
            {
                yatest_err("yatest_output_stream_write_consistency_test: %s: chunk_size=%i, factory failed with %i/%08x", name, chunk_size, ret, ret);
                return 1;
            }
            if(sample_size != model_size)
            {
                yatest_err(
                    "yatest_output_stream_write_consistency_test: %s: chunk_size=%i, model (%i) and sample (%i) size "
                    "differ",
                    name,
                    chunk_size,
                    model_size,
                    sample_size);
                return 1;
            }
            for(uint32_t offset = 0; offset < model_size; offset += chunk_size)
            {
                ret = output_stream_write_fully(&os, &random_array[offset], MIN(chunk_size, model_size - offset));
                if(FAIL(ret))
                {
                    yatest_err("yatest_output_stream_write_consistency_test: %s: chunk_size=%i, write at %i failed with %s", name, chunk_size, offset, error_gettext(ret));
                    return 1;
                }
                if(flushes)
                {
                    output_stream_flush(&os);
                }
            }
            ret = readback(&os, (void **)&stream_array, &stream_array_size);
            if(ret != 0)
            {
                yatest_err("yatest_output_stream_write_consistency_test: %s: chunk_size=%i, failed to read-back model with %s", name, chunk_size, error_gettext(ret));
                return ret;
            }
            if(stream_array_size != model_size)
            {
                yatest_err("yatest_output_stream_write_consistency_test: %s: model (%i) and read-back size (%i) differ", name, model_size, stream_array_size);
                return 1;
            }

            if(memcmp(stream_array, random_array, model_size) != 0)
            {
                yatest_err("yatest_output_stream_write_consistency_test: %s: model and read-back content differ for size %i", name, model_size);
                return 1;
            }

            free(stream_array);
            stream_array = NULL;
            stream_array_size = 0;
        }
    }
    return 0;
}

/**
 * Values should always be 1 for the small read, 4K+1 for the big read and the increment should be 1.
 */
int yatest_input_stream_skip_consistency_test(yatest_input_stream_factory *factory, uint32_t size, uint32_t small_read, uint32_t big_read, uint32_t increment, char *name)
{
    input_stream_t is;
    int            ret;

    // instantiate and read the steam

    uint32_t model_size = size;
    ret = factory(&is, &model_size);
    if(ret != 0)
    {
        yatest_err("yatest_input_stream_read: %s: failed to instantiate model", name);
        return ret;
    }

    char *model = (char *)malloc(model_size);
    ret = input_stream_read_fully(&is, model, model_size);
    if(ret != (int)model_size)
    {
        yatest_err("yatest_input_stream_read: %s: failed to read model: size=%u, real=%u, ret=%i", name, size, model_size, ret);
        return ret;
    }

    ret = input_stream_skip(&is, 0);
    if(ret != 0)
    {
        yatest_err("yatest_input_stream_read: %s: expected to read exacly 0 bytes, got %i/%08x", name, ret, ret);
        return ret;
    }

    input_stream_close(&is);

    // for all combinations, read that same stream and compare

    uint8_t *sample = (uint8_t *)malloc(model_size);

    for(uint32_t chunk_size = small_read; chunk_size <= big_read; chunk_size += increment)
    {
        // ensure the content is absolutely different from the expectations
        for(uint32_t i = 0; i < model_size; ++i)
        {
            sample[i] = ~model[i];
        }

        for(int pass = 0; pass < 2; ++pass)
        {
            uint32_t sample_size;
            sample_size = model_size;
            ret = factory(&is, &model_size);
            if(ret != 0)
            {
                yatest_err("yatest_input_stream_read: %s: failed to instantiate sample with size %u", name, model_size);
                return ret;
            }

            if(model_size != sample_size)
            {
                yatest_err("yatest_input_stream_read: %s: failed to instantiate a sample of the right size: %u instead of %u", name, sample_size, model_size);
                input_stream_close(&is);
                return 1;
            }

            uint8_t       *p = sample;
            const uint8_t *limit = sample + sample_size;

            for(int alt = pass; p < limit; alt ^= 1)
            {
                if(alt == 0)
                {
                    ret = input_stream_read(&is, p, chunk_size); // don't use the "fully" version
                }
                else
                {
                    ret = input_stream_skip(&is, chunk_size); // don't use the "fully" version
                }
                if(ret <= 0)
                {
                    yatest_err("yatest_input_stream_read: %s: unexpected error or EOF %s sample: %i=%08x instead of %u", name, (alt == 0) ? "reading" : "skipping", ret, ret, chunk_size);
                    input_stream_close(&is);
                    return 2;
                }
                p += ret;
            }

            input_stream_close(&is);
        }

        if(memcmp(model, sample, model_size) != 0)
        {
            yatest_err("yatest_input_stream_read: %s: model and sample differ for chunk size %u", name, chunk_size);
            return 3;
        }
    }

    free(sample);
    free(model);

    return 0;
}

// because close isn't a guarantee

int yatest_close_nointr(int fd)
{
    for(;;)
    {
        int ret = close(fd);
        if(ret < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
        }
        return ret;
    }
}

void yatest_bytearray_hexdump_next(input_stream_t *bais, uint32_t next)
{
    const uint8_t *buffer = bytearray_input_stream_buffer(bais);
    uint32_t       offset = bytearray_input_stream_offset(bais);
    const uint8_t *limit = buffer + bytearray_input_stream_size(bais);
    buffer += offset;
    limit = MIN(limit, buffer + next);

    yatest_hexdump(buffer, limit);
}

void yatest_file_getname(int size, char *out_name, size_t name_size) { snprintf(out_name, name_size, "/tmp/yatest-file-%i", size); }

void yatest_file_create(int size)
{
    char filename[64];
    yatest_file_getname(size, filename, sizeof(filename));
    unlink(filename);
    FILE *f = fopen(filename, "w+");
    if(f == NULL)
    {
        int err = errno;
        yatest_err("yatest_file_create: create '%s' failed: %s", filename, strerror(err));
        exit(1);
    }
    if(size > 0)
    {
        input_stream_t ris;
        yatest_random_input_stream_init(&ris, size);
        char *buffer = (char *)malloc(size);
        input_stream_read(&ris, buffer, size);
        if(fwrite(buffer, size, 1, f) != 1)
        {
            int err = errno;
            yatest_err("yatest_file_create: write '%s' failed: %s", filename, strerror(err));
            exit(1);
        }
    }
    fclose(f);
}

void yatest_file_create_empty(int size)
{
    char filename[64];
    yatest_file_getname(size, filename, sizeof(filename));
    unlink(filename);
    FILE *f = fopen(filename, "w+");
    if(f == NULL)
    {
        int err = errno;
        yatest_err("yatest_file_create_empty: create '%s' failed: %s", filename, strerror(err));
        exit(1);
    }
    fclose(f);
}

void yatest_file_create_with(const char *name, const void *buffer, size_t buffer_size)
{
    FILE *f = fopen(name, "w+");
    if(f != NULL)
    {
        fwrite(buffer, buffer_size, 1, f);
        fclose(f);
    }
    else
    {
        int err = errno;
        yatest_err("yatest_file_create_with(%s) failed with %s", name, strerror(err));
        exit(1);
    }
}

void yatest_file_delete(int size)
{
    char filename[64];
    yatest_file_getname(size, filename, sizeof(filename));
    unlink(filename);
}
