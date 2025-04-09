# FridaHunter.cpp

**FridaHunter.cpp** es una poderosa herramienta en C++ para detectar la presencia de herramientas de hooking y análisis dinámico como **Frida** en dispositivos Android. Diseñado para integrarse con aplicaciones mediante JNI, este sistema ejecuta múltiples pruebas heurísticas para asegurar la integridad de la app en tiempo de ejecución.

## 🧠 ¿Qué Detecta?

- Puertos utilizados por Frida (`27042`, `27043`, etc.)
- Procesos y comandos sospechosos relacionados con `frida`, `gadget`, etc.
- Archivos y bibliotecas en memoria vinculados a Frida
- Hooks sobre funciones sensibles (`open`, `connect`)
- Artefactos en el filesystem: `/data`, `/system`, `libfrida*.so`
- Variables de entorno (`LD_PRELOAD`)
- Contextos SELinux alterados
- Paquetes de red con rastros de Frida
- Anomalías en el tiempo de ejecución (timing attacks)
- Lecturas directas en memoria (`/proc/self/mem`)

## 🛠️ Integración con Android (JNI)

Para utilizar FridaHunter en tu app Android mediante NDK, declara la función JNI de esta forma:

```cpp
extern "C"
JNIEXPORT jboolean JNICALL
Java_<package-name>_detectFrida(JNIEnv *env, jobject thiz) {
    bool detected = FridaHunter::isFridaDetected();
    return detected ? JNI_TRUE : JNI_FALSE;
}
```

Asegúrate de reemplazar `<package-name>` por el paquete/clase de tu proyecto.

## 📁 Estructura del Proyecto

```plaintext
FridaHunter.cpp
├── FridaHunter namespace
│   ├── checkSuspiciousPorts()
│   ├── checkFridaProcesses()
│   ├── checkMemoryMaps()
│   ├── checkSyscallTampering()
│   ├── checkFilesystemArtifacts()
│   ├── checkEnvironment()
│   ├── checkSELinuxContext()
│   ├── checkNetworkTraffic()
│   ├── checkExecutionTiming()
│   ├── checkMemoryTraces()
│   └── isFridaDetected()
└── JNI Interface
    └── Java_<package-name>_detectFrida()
```

## 📦 Requisitos

- Android NDK (21+)
- CMake o ndk-build
- Permisos adecuados para leer `/proc`, `/data`, y abrir sockets
- Compatible con Android 5.0+

## 🔐 Recomendaciones

- Ejecutar estas comprobaciones en segundo plano o en momentos clave del ciclo de vida de la app.
- Combina este detector con otras medidas anti-tampering para una seguridad más robusta.

---

> **Nota**: Ningún método de detección es 100% infalible. FridaHunter emplea múltiples técnicas para aumentar la probabilidad de detección, pero se recomienda su uso como parte de una estrategia de seguridad más amplia.
