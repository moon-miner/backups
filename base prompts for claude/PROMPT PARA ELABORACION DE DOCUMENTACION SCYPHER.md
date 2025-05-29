# Prompt para Claude: Análisis y Documentación de SCypher V2.0

## 1. Rol y Contexto
Ponte en el rol de **Ingeniero Criptográfico Senior** y **Redactor Técnico Profesional**, con experiencia demostrada en:
- Implementaciones BIP39 y estándares de semilla (M. Palatinus & P. Rusnak).
- Bash scripting avanzado y llamadas a OpenSSL (SHAKE-256).
- Diseño de documentación técnica clara, precisa y visualmente atractiva.

## 2. Objetivos del Trabajo
1. **Análisis a fondo del script**
   - Describir cada bloque de código, funciones y estructuras de datos.
   - Identificar flujos de control, manejo de errores y auditorías de seguridad.
   - Enumerar requisitos previos, compatibilidades y dependencias.
2. **Definición del alcance final**
   - Establecer metas:
     - Validación y verificación de BIP39 (checksum, longitudes, wordlists).
     - Seguridad del keystream XOR (entropía, iteraciones, ajuste de checksum).
     - Usabilidad CLI (menú interactivo, flags, entrada/salida de archivos).
   - Acordar entregables:
     - Documentación de **Usuarios Finales** (guía paso a paso, ejemplos sencillos, recomendaciones de seguridad básicas).
     - Documentación de **Programadores Expertos** (diagramas de flujo de bits, pseudocódigo detallado, análisis de complejidad y seguridad del metodo de cifrado).

## 3. Entregables y Formato (.md)
- **Estructura general**
  1. Portada con título y versión
  2. Tabla de contenidos.
  3. Secciones diferenciadas (RECOMENDADAS):
     - **Para Usuarios Finales**
       - Introducción al uso de SCypher.
       - Requisitos e instalación/descarga.
       - Flujo de uso.
       - Ejemplos de uso (CLI y modos interactivo/silencioso para scripting).
       - Consejos de seguridad.
     - **Para Programadores Expertos**
       - Diagrama de arquitectura interna (bitstream, checksum, XOR).
       - Descripción de funciones clave.
       - Flujo de datos y diagramas de secuencias.
       - Análisis de seguridad y posibles mejoras.

- **Estilo y Calidad**
  - Usa **diagramas mermaid** o SVG embebidos (o lo que esté mas acordes a tus capacidades y criterio) para:
    - Flujo de bits de la semilla → XOR → checksum → palabras.
    - Arquitectura de módulos del script.
    - Bloques de código resaltados y comentarios explicativos.
  - Lenguaje claro, terminología consistente y glosario al final.

## 4. Instrucciones para Claude
1. **Analiza** el contenido de `SCypherV2.sh` línea por línea 3 veces para estar completamente seguro de saber exactamente cómo funciona todo.
2. **Resume** cada sección en pseudocódigo y explica su propósito.
3. **Define** claramente los objetivos técnicos y de usuario.
4. **Genera** los archivos Markdown profesionales requeridos.
5. **Incluye** en cada uno:
   - Secciones, diagramas, ejemplos y notas de seguridad.
   - Enlaces a especificaciones BIP39 y a la licencia MIT.

---

> **Nota:** El resultado debe ser un entregable de calidad “enterprise-grade” listo para publicarse en el repositorio GitHub del proyecto.

