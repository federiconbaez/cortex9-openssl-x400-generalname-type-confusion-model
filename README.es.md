# cortex9-openssl-x400-generalname-type-confusion-model

Modelo de heap etiquetado de **CVE-2023-0286**: confusión de tipos de la
dirección X.400 en `GENERAL_NAME_cmp` de OpenSSL (corregido en 3.0.8,
1.1.1t y 1.0.2zg). Educativo, offline y determinista.

- Los comparadores leen **bytes del modelo** en direcciones del modelo.
- Una lectura fuera de una asignación se informa, no se realiza.
- No se construye ningún certificado ni CRL.

## El fallo

- **Declaración:** `d.x400Address` estaba declarado como `ASN1_TYPE *`.
- **Decodificación:** el decodificador construye un `ASN1_STRING` con el
  TLV completo y `type = 16` (`v3_genn.c:37`, `tasn_dec.c:757-782`).
- **Comparación:** `ASN1_TYPE_cmp` lee `type` (que en realidad es la
  longitud) y `value.ptr` (que en realidad es `data`).
- **Ramas según la longitud:**
  - **longitud 5:** compara igual sin leer nada (`V_ASN1_NULL`);
  - **longitud 6:** `OBJ_cmp` lee 40 bytes;
  - **el resto:** `ASN1_STRING_cmp` lee 24 bytes del TLV. Con 16 bytes o
    más, los bytes 8..16 del contenido se convierten en el puntero de
    `memcmp`.
- **El fix** 7880536 declara `ASN1_STRING *` y llama a `ASN1_STRING_cmp`.

## Resultados

Barrido de longitudes de 2 a 64, con un par idéntico y otro que difiere
en el último byte:

- **Antes del fix:**
  - 98 lecturas por puntero salvaje;
  - 25 lecturas más allá de la asignación;
  - 1 resultado erróneo;
  - 2 respuestas correctas.
- **Con el fix:** las 126 comparaciones son correctas y todas las
  lecturas quedan dentro de las asignaciones.
- **Control contrafactual:** con un `ASN1_TYPE` real, como el declarado,
  el comparador antiguo acierta.

`scripts/derive_expected.py` deriva cada etiqueta por su cuenta con
`struct` de Python.

Ver [LIMITATIONS.md](LIMITATIONS.md), [SOURCES.md](SOURCES.md) y
[PRACTICE.md](PRACTICE.md). Licencia: Apache-2.0.
