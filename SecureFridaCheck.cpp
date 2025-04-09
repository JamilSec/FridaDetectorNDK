#include <jni.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <cstdio>
#include <cstdlib>
#include <jni.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <glob.h>

// Si el NDK no proporciona las funciones SELinux, definimos stubs.
// Puedes comentar o ajustar estas implementaciones según necesites.
extern "C" {
int getfilecon(const char* path, char** con) {
    // Stub: no se pudo obtener el contexto SELinux.
    return -1;
}
void freecon(char* con) {
    // Stub: no se realiza ninguna acción.
}
}

#define TAG "FridaDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// Alias para las funciones sobrecargadas.
using open_func_t = int(*)(const char*, int, ...);
using connect_func_t = int(*)(int, const struct sockaddr*, socklen_t);

//
// Funciones auxiliares para la detección de artefactos en Filesystem
//
bool fileExists(const std::string &path) {
    struct stat sb;
    return (stat(path.c_str(), &sb) == 0);
}

bool checkFilesWithPrefixInDir(const std::string &directory, const std::string &prefix) {
    DIR* dir = opendir(directory.c_str());
    if (!dir) return false;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Revisamos archivos regulares, enlaces simbólicos o de tipo desconocido
        if (entry->d_type == DT_REG || entry->d_type == DT_LNK || entry->d_type == DT_UNKNOWN) {
            std::string name(entry->d_name);
            if (name.find(prefix) == 0) {  // Empieza con el prefijo indicado
                closedir(dir);
                return true;
            }
        }
    }
    closedir(dir);
    return false;
}

namespace FridaHunter {

    // 1. Detección de Puertos (incluye TCP+UDP)
    bool checkSuspiciousPorts() {
        const std::vector<int> FRIDA_PORTS = {27042, 27043, 27047, 27049, 4242, 7331};

        // Lambda que escanea archivos de red
        auto scanProcNet = [=](const char* path) -> bool {
            std::ifstream file(path);
            std::string line;
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                std::string token;
                iss >> token; // Se obtiene local_address
                size_t colon = token.find_last_of(':');
                if (colon != std::string::npos) {
                    try {
                        int port = std::stoi(token.substr(colon + 1), nullptr, 16);
                        for (int p : FRIDA_PORTS) {
                            if (port == p)
                                return true;
                        }
                    } catch (...) {
                        // Se ignoran errores de conversión
                    }
                }
            }
            return false;
        };

        return scanProcNet("/proc/net/tcp") || scanProcNet("/proc/net/udp");
    }

    // 2. Detección de Procesos (búsqueda en /proc)
    bool checkFridaProcesses() {
        DIR* dir = opendir("/proc");
        if (!dir) return false;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            std::string pid(entry->d_name);
            std::string path = "/proc/" + pid + "/cmdline";
            std::ifstream cmdline(path);
            std::string content((std::istreambuf_iterator<char>(cmdline)),
                                std::istreambuf_iterator<char>());
            if (content.find("frida") != std::string::npos ||
                content.find("gadget") != std::string::npos ||
                content.find("re.frida.server") != std::string::npos) {
                closedir(dir);
                return true;
            }
        }
        closedir(dir);
        return false;
    }

    // 3. Detección de Archivos en Memoria (mapas sospechosos)
    bool checkMemoryMaps() {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("frida") != std::string::npos ||
                line.find("gadget") != std::string::npos ||
                line.find("linjector") != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    // 4. Detección de Hooks (Intercepción de syscalls)
    bool checkSyscallTampering() {
        auto orig_open = (open_func_t)dlsym(RTLD_NEXT, "open");
        auto orig_connect = (connect_func_t)dlsym(RTLD_NEXT, "connect");

        void* self_handle = dlopen("libc.so", RTLD_NOW);
        if (!self_handle) return false;
        auto real_open = (open_func_t)dlsym(self_handle, "open");
        auto real_connect = (connect_func_t)dlsym(self_handle, "connect");
        dlclose(self_handle);

        return (orig_open != real_open) || (orig_connect != real_connect);
    }

    // 5. Detección de Artefactos en Filesystem (usando búsqueda en directorios)
    bool checkFilesystemArtifacts() {
        if (checkFilesWithPrefixInDir("/data/local/tmp", "frida"))
            return true;
        if (checkFilesWithPrefixInDir("/data/local/tmp", "re.frida.server"))
            return true;

        DIR* dataDir = opendir("/data/data");
        if (dataDir) {
            struct dirent* entry;
            while ((entry = readdir(dataDir)) != nullptr) {
                if (entry->d_type == DT_DIR) {
                    std::string packageDir = std::string("/data/data/") + entry->d_name;
                    std::string cacheDir = packageDir + "/cache";
                    if (checkFilesWithPrefixInDir(cacheDir, "frida")) {
                        closedir(dataDir);
                        return true;
                    }
                }
            }
            closedir(dataDir);
        }

        DIR* sysLibDir = opendir("/system/lib");
        if (sysLibDir) {
            struct dirent* entry;
            while ((entry = readdir(sysLibDir)) != nullptr) {
                if (entry->d_type == DT_REG || entry->d_type == DT_LNK || entry->d_type == DT_UNKNOWN) {
                    std::string filename(entry->d_name);
                    if (filename.find("libfrida") == 0 && filename.size() >= 7 &&
                        filename.substr(filename.size() - 3) == ".so") {
                        closedir(sysLibDir);
                        return true;
                    }
                }
            }
            closedir(sysLibDir);
        }

        if (fileExists("/system/app/frida-server"))
            return true;

        return false;
    }

    // 6. Detección de Entorno (uso de getenv en lugar de environ)
    bool checkEnvironment() {
        // Verificar LD_PRELOAD
        const char* ld_preload = getenv("LD_PRELOAD");
        if (ld_preload && std::string(ld_preload).find("frida") != std::string::npos) {
            return true;
        }
        // Se puede ampliar la comprobación buscando variables conocidas:
        // Por ejemplo: "FRIDA_PORT" u otras según convenga.
        return false;
    }

    // 7. Detección de Firmware Modificado (SELinux Context)
    bool checkSELinuxContext() {
        struct stat st;
        if (stat("/data/local/tmp", &st) == 0) {
            char* ctx = nullptr;
            if (getfilecon("/data/local/tmp", &ctx) >= 0 && ctx) {
                std::string context(ctx);
                freecon(ctx);
                if (context.find("frida") != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    // 8. Detección de Tráfico de Red Anómalo (captura RAW TCP)
    bool checkNetworkTraffic() {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) return false;
        timeval tv{1, 0}; // Timeout de 1 segundo.
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char buffer[1024];
        ssize_t bytes = recv(sock, buffer, sizeof(buffer), 0);
        close(sock);
        if (bytes > 0) {
            std::string data(buffer, bytes);
            return data.find("frida") != std::string::npos;
        }
        return false;
    }

    // 9. Detección de Tiempo de Ejecución (Timing Attack)
    bool checkExecutionTiming() {
        auto start = std::chrono::high_resolution_clock::now();
        volatile int dummy = 0;
        for (int i = 0; i < 1000000; ++i)
            dummy ^= i;
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return duration.count() > 15; // Baseline ajustado para 2025
    }

    // 10. Detección de Rastros en Memoria
    bool checkMemoryTraces() {
        std::ifstream mem("/proc/self/mem", std::ios::binary);
        if (!mem) return false;
        const std::string PATTERN = "LIBFRIDA";
        char buffer[1024];
        for (size_t offset = 0; offset < 0x100000; offset += sizeof(buffer)) {
            mem.seekg(offset);
            mem.read(buffer, sizeof(buffer));
            std::streamsize count = mem.gcount();
            if (count > 0) {
                if (std::search(buffer, buffer + count, PATTERN.begin(), PATTERN.end()) != buffer + count) {
                    return true;
                }
            }
        }
        return false;
    }

    bool isFridaDetected() {
        return checkSuspiciousPorts()      ||
               checkFridaProcesses()         ||
               checkMemoryMaps()             ||
               checkSyscallTampering()       ||
               checkFilesystemArtifacts()    ||
               checkEnvironment()            ||
               checkSELinuxContext()         ||
               checkNetworkTraffic()         ||
               checkExecutionTiming()        ||
               checkMemoryTraces();
    }
}
