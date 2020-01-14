#pragma once

#include <stdexcept>
#include <stdio.h>

#include <openssl/bio.h>

#include "ssl-util.h"

namespace my {

inline my::UniquePtr<BIO>
make_eavesdrop_bio(const char *name)
{
    constexpr auto print_bytes = [](const char *data, int nbytes) {
        if (nbytes > 0) {
            printf(": ");
            for (int i=0; i < nbytes && i < 10; ++i) {
                if (32 <= data[i] && data[i] <= 126) putchar(data[i]);
                else printf("\\x%02X", (unsigned char)data[i]);
            }
            if (nbytes > 10) printf(" ...");
        }
        printf("\n");
    };

    static auto methods = []() {
        auto methods = my::UniquePtr<BIO_METHOD>(BIO_meth_new(BIO_TYPE_FILTER, "EavesdropBIO"));
        if (methods == nullptr) {
            throw std::runtime_error("EavesdropBIO: error in BIO_meth_new");
        }
        BIO_meth_set_read(methods.get(), [](BIO *bio, char *data, int len) -> int {
            const char *name = reinterpret_cast<const char *>(BIO_get_data(bio));
            printf("EVE %s: asked to read %d bytes\n", name, len);
            int nbytes = BIO_read(BIO_next(bio), data, len);
            printf("EVE %s: read %d (of %d) bytes", name, nbytes, len);
            print_bytes(data, nbytes);
            return nbytes;
        });
        BIO_meth_set_write(methods.get(), [](BIO *bio, const char *data, int len) -> int {
            const char *name = reinterpret_cast<const char *>(BIO_get_data(bio));
            printf("EVE %s: asked to write %d bytes", name, len);
            print_bytes(data, len);
            int nbytes = BIO_write(BIO_next(bio), data, len);
            printf("EVE %s: wrote %d (of %d) bytes", name, nbytes, len);
            print_bytes(data, nbytes);
            return nbytes;
        });
        BIO_meth_set_ctrl(methods.get(), [](BIO *bio, int cmd, long num, void *ptr) -> long {
            const char *name = reinterpret_cast<const char *>(BIO_get_data(bio));
            if (cmd == BIO_CTRL_FLUSH) {
                printf("EVE %s: asked to flush\n", name);
            }
            long result = BIO_ctrl(BIO_next(bio), cmd, num, ptr);
            if (cmd == BIO_CTRL_FLUSH) {
                printf("EVE %s: flushed\n", name);
            }
            return result;
        });
        return methods;
    }();

    auto bio = my::UniquePtr<BIO>(BIO_new(methods.get()));
    if (bio == nullptr) {
        throw std::runtime_error("EavesdropBIO: error in BIO_new");
    }
    BIO_set_data(bio.get(), (void *)name);
    BIO_set_init(bio.get(), 1);
    return bio;
}

} // namespace my
