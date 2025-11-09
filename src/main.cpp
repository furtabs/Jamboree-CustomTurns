#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>

// --- Helpers -----------------------------------------------------------------
static uint8_t* find_pattern(uint8_t* start, size_t size, const uint8_t* pattern, size_t len) {
    if (len == 0 || size < len) return nullptr;
    uint8_t* end = start + size - len + 1;
    for (uint8_t* p = start; p < end; ++p) {
        if (memcmp(p, pattern, len) == 0) return p;
    }
    return nullptr;
}

static bool patch_bytes(void* address, const uint8_t* data, size_t len) {
    if (!address || !data || len == 0) return false;

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)address;
    uintptr_t page_start = addr & ~(page_size - 1);
    uintptr_t page_end = ((addr + len - 1) & ~(page_size - 1)) + page_size;
    size_t prot_size = page_end - page_start;

    if (mprotect((void*)page_start, prot_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;

    memcpy((void*)addr, data, len);
    __builtin___clear_cache((char*)addr, (char*)(addr + len));
    mprotect((void*)page_start, prot_size, PROT_READ | PROT_EXEC);

    return true;
}

// --- hkMain -----------------------------------------------------------------
extern "C" void hkMain() {
    // Full byte pattern from your dump (partial is enough to uniquely identify it)
    const uint8_t pattern[] = {
        0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xd4,0x2a,0x33,0x00,0x71,0x00,0x00,0x00,
        0xf4,0x2a,0x33,0x00,0x71,0x00,0x00,0x00,
        0x00,0x2b,0x33,0x00,0x71,0x00,0x00,0x00
        // You can add more bytes if necessary for uniqueness
    };

    uint8_t* start = reinterpret_cast<uint8_t*>(0x100000000); // Start search at a reasonable memory base
    size_t search_size = 0x2000000; // 32 MB search window; adjust as needed

    uint8_t* found = find_pattern(start, search_size, pattern, sizeof(pattern));
    if (found) {
        uint8_t new_bytes[4] = { 0x0A, 0x00, 0x00, 0x00 }; // 10 coins
        patch_bytes(found, new_bytes, sizeof(new_bytes));
        // optionally log success
    }
}
