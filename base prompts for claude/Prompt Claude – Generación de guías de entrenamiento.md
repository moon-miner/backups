# 🧠 Prompt Técnico para Claude IA: Generación de Guía Markdown Basada en Implementación Exitosa

## 🧩 Contexto

Acabo de completar con éxito la implementación de una característica/lógica compleja en un entorno de desarrollo real. Esta implementación fue rigurosa, superó desafíos técnicos y representa una solución de alta calidad y aplicabilidad.

## 🎯 Objetivo del Prompt

Quiero que te pongas en el rol de un **ingeniero técnico senior especializado en documentación y transferencia de conocimiento para IA (especialmente Claude IA)**.

Utilizando **todo el conocimiento práctico y técnico que adquiriste durante el proceso de implementación** de esta característica, quiero que elabores una guía técnica definitiva y autónoma en formato `.md` Markdown, **ideal tanto para el aprendizaje humano como para el entrenamiento de modelos de IA**.

---

## 🧠 Rol y Estilo Esperado

<role>Ingeniero experto en sistemas distribuidos, documentación técnica avanzada y entrenamiento de modelos de lenguaje.</role>

<tone>Profesional, claro, didáctico, y orientado a transferencia de conocimiento.</tone>

<target_audience>
- Ingenieros de software con experiencia que deseen implementar {{NOMBRE_CARACTERISTICA_EN_MAYUSCULAS}}
- Entrenadores de modelos de lenguaje que buscan ejemplos de código y estructura para fine-tuning
</target_audience>

---

## ✍️ Instrucciones para la Generación de la Guía

<instructions>
1. Genera una guía técnica completa y bien estructurada en formato `.md` Markdown.
2. Divide el contenido en secciones claras con títulos jerarquizados.
3. Incluye ejemplos de código funcionales con anotaciones que expliquen los pasos.
4. Cita documentación oficial y enlaces relevantes en cada sección (cuando corresponda).
5. Si el tema requiere archivos grandes complementarios (por ejemplo, scripts `.js`, `.py`, `.env`, `.json`, etc.), genera esos archivos en secciones separadas al final de la guía principal y refiérete a ellos en la guía con su nombre exacto.
6. Incluye un bloque especial (solo si es útil) en formato de prompt específico para Claude IA utilizando XML tags del sistema de Anthropic.
7. Asegúrate de que la guía sirva tanto como **documentación técnica para humanos** como para **alimentar un dataset de entrenamiento para IA**.
</instructions>

---

## 📦 Especificaciones de Salida

<format>
- Formato final: Markdown `.md`
- Incluye todos los archivos técnicos si son necesarios (anexados en bloques separados)
- La guía debe ser autónoma y autoexplicativa
</format>

<structure>
1. Introducción y objetivos de la característica
2. Arquitectura y conceptos clave involucrados
3. Implementación técnica paso a paso
4. Código fuente comentado
5. Testing y validación
6. Manejo de errores y debugging
7. Recursos y documentación oficial
8. (Opcional) Prompt de ejemplo optimizado para Claude
9. (Opcional) Archivos complementarios nombrados y explicados
</structure>

---

## 🧠 Título de la Guía

El título principal de la guía debe ser:

```markdown
# 🧭 Guía Técnica: Implementación de {{NOMBRE_CARACTERISTICA_EN_MAYUSCULAS}}

