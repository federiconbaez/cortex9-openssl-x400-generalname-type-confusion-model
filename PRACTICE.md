# Guía práctica (8 niveles)

Ejercicios **offline y locales** sobre un heap de juguete. No se construye
ningún certificado ni CRL y no se lee memoria real. Cada respuesta está
comprobada por `tests/practice.rs` (`practice_level_N`).

Comando: `cargo run --release --bin x400-cmp-model -- cmp <pre|fix>
<decoded|declared> <hex a> <hex b>`.

1. **Qué guarda el decodificador.** Lee `tasn_dec.c:757-782`. ¿Qué
   `length` y `type` tiene el `ASN1_STRING` de `a3 00`?
   (`practice_level_1`: 2 y 16)
2. **El campo equivocado.** Con los layouts LP64, ¿de qué campo sale
   `ASN1_TYPE.type`? (`practice_level_2`: de `length`, vale 2)
3. **La regresión de upstream.** ¿En qué línea se detiene `a3 00` y cuántos
   bytes faltan? (`practice_level_3`: `asn1_lib.c:392`, 2 bytes)
4. **Igualdad falsa.** Con longitud 5, ¿por qué dos direcciones distintas
   comparan igual? (`practice_level_4`: rama `V_ASN1_NULL`, resultado 0)
5. **La rama OBJECT.** ¿Qué lee `OBJ_cmp` con un TLV de 6 bytes?
   (`practice_level_5`: `obj_lib.c:60 a->length`, fuera de la asignación)
6. **El puntero del aviso.** Con un TLV de 24 bytes, ¿de dónde sale el
   puntero que recibe `memcmp`? (`practice_level_6`: bytes 8..16 del
   contenido; aquí 0x4141414141414141, inerte)
7. **El fix.** ¿Qué compara ahora `ASN1_STRING_cmp`?
   (`practice_level_7`: longitud, bytes y tipo reales)
8. **Control.** Si el campo fuera de verdad un `ASN1_TYPE`, ¿fallaría el
   comparador antiguo? (`practice_level_8`: no)

Más allá: añade un caso a `fixtures/cases.json`, deriva su etiqueta con
`python3 scripts/derive_expected.py > fixtures/expected.json` y comprueba
con `cargo test`.

*English summary: eight offline levels on the field-by-field reinterpretation;
every answer is asserted by `tests/practice.rs`.*
